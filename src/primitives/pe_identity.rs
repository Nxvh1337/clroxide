//! Pure Rust PE metadata parser to extract .NET assembly identity
//!
//! This replaces the broken ICLRAssemblyIdentityManager approach which fails with
//! HRESULT(0x80040154) REGDB_E_CLASSNOTREG because:
//!   1. CLSID_CLRAssemblyIdentityManager was incorrect
//!   2. ICLRRuntimeInfo::GetInterface does NOT support ICLRAssemblyIdentityManager
//!
//! This parser reads the CLI header and metadata tables directly from the PE bytes
//! to produce: "AssemblyName, Version=w.x.y.z, Culture=neutral, PublicKeyToken=null"

use std::convert::TryInto;

// Helper to read a little-endian u16 from a byte slice at a given offset
fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}

// Helper to read a little-endian u32 from a byte slice at a given offset
fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

// Read a null-terminated UTF-8 string from the strings heap at `offset`
fn read_string(strings_heap: &[u8], offset: usize) -> String {
    let start = offset;
    let end = strings_heap[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strings_heap.len());
    String::from_utf8_lossy(&strings_heap[start..end]).to_string()
}

/// Extract a .NET assembly identity string from raw PE bytes.
///
/// Returns a string like:
/// `MyAssembly, Version=1.2.3.4, Culture=neutral, PublicKeyToken=null`
pub fn get_assembly_identity_from_bytes(data: &[u8]) -> Result<String, String> {
    let layout = parse_metadata_layout(data)?;
    let strings = data
        .get(layout.strings_heap_offset..layout.strings_heap_offset + layout.strings_heap_size)
        .ok_or("Strings heap out of bounds")?;
    let blob = data
        .get(layout.blob_heap_offset..layout.blob_heap_offset + layout.blob_heap_size)
        .unwrap_or(&[]);

    let row_off = layout.assembly_def_row_offset;
    let string_idx_size = layout.string_idx_size;
    let blob_idx_size = layout.blob_idx_size;
    let string_index_wide = string_idx_size == 4;
    let blob_index_wide = blob_idx_size == 4;

    let major = read_u16(data, row_off + 4).ok_or("Cannot read MajorVersion")?;
    let minor = read_u16(data, row_off + 6).ok_or("Cannot read MinorVersion")?;
    let build = read_u16(data, row_off + 8).ok_or("Cannot read BuildNumber")?;
    let revision = read_u16(data, row_off + 10).ok_or("Cannot read RevisionNumber")?;

    let pk_offset = row_off + 16;
    let pk_blob_idx = if blob_index_wide {
        read_u32(data, pk_offset).ok_or("Cannot read PublicKey blob index")? as usize
    } else {
        read_u16(data, pk_offset).ok_or("Cannot read PublicKey blob index")? as usize
    };

    let name_offset = pk_offset + blob_idx_size;
    let name_str_idx = if string_index_wide {
        read_u32(data, name_offset).ok_or("Cannot read Name string index")? as usize
    } else {
        read_u16(data, name_offset).ok_or("Cannot read Name string index")? as usize
    };

    let culture_offset = name_offset + string_idx_size;
    let culture_str_idx = if string_index_wide {
        read_u32(data, culture_offset).ok_or("Cannot read Culture string index")? as usize
    } else {
        read_u16(data, culture_offset).ok_or("Cannot read Culture string index")? as usize
    };

    let name = read_string(strings, name_str_idx);
    let culture_raw = read_string(strings, culture_str_idx);
    let culture = if culture_raw.is_empty() {
        "neutral".to_string()
    } else {
        culture_raw
    };

    let public_key_token = get_public_key_token(blob, pk_blob_idx);

    if name.is_empty() || name_str_idx >= strings.len() {
        return Err(format!(
            "PE identity parse failed: name index {} is out of range (offset={}). \
             Assembly table row may be at wrong offset - check table row size calculations.",
            name_str_idx, row_off
        ));
    }
    if name.contains('\0') || name.chars().any(|c| c < ' ' && c != '\t') {
        return Err(format!(
            "PE identity parse failed: assembly name {:?} contains invalid characters. \
             Table offset calculation may be wrong.",
            name
        ));
    }

    Ok(format!(
        "{}, Version={}.{}.{}.{}, Culture={}, PublicKeyToken={}",
        name, major, minor, build, revision, culture, public_key_token
    ))
}

/// Overwrite the AssemblyDef BuildNumber and RevisionNumber fields in place.
///
/// Forces the CLR's hosted-runtime binder to treat the assembly as a brand-new
/// identity on every load — necessary when the same assembly bytes need to be
/// re-executed multiple times in the same process (the binder caches by full
/// identity, and cached assemblies retain their static state from the prior
/// `Main()` invocation, which breaks run-once entrypoints).
pub fn patch_assembly_version(
    data: &mut [u8],
    build: u16,
    revision: u16,
) -> Result<(), String> {
    let layout = parse_metadata_layout(data)?;
    let row_off = layout.assembly_def_row_offset;
    if row_off + 12 > data.len() {
        return Err("AssemblyDef row truncated".into());
    }
    data[row_off + 8..row_off + 10].copy_from_slice(&build.to_le_bytes());
    data[row_off + 10..row_off + 12].copy_from_slice(&revision.to_le_bytes());
    Ok(())
}

/// Overwrite the Module table's Mvid (Module Version Id) GUID in place with a
/// nonce-derived value.
///
/// The Mvid is a per-build GUID embedded by the compiler that the CLR uses to
/// dedupe assemblies process-wide. When the *same* compiled bytes are loaded
/// into two different AppDomains under different simple names (as we do for
/// repeat ExecuteAssembly invocations), the binder of the second AD sees a
/// pre-existing assembly with the same Mvid loaded under the first name and
/// fails the load with `FUSION_E_REF_DEF_MISMATCH (0x80131040)` because the
/// requested name no longer matches the cached entry's name.
///
/// Patching the Mvid forces the CLR to treat each task's bytes as a freshly
/// compiled assembly, so the binder cache lookup misses and a clean load
/// proceeds.
///
/// The new GUID is `nonce` repeated four times (16 bytes) — uniqueness within
/// the host process is the only requirement.
pub fn patch_module_mvid(data: &mut [u8], nonce: u32) -> Result<(), String> {
    let layout = parse_metadata_layout(data)?;
    if layout.guid_heap_size == 0 {
        return Err("No #GUID heap — cannot patch Mvid".into());
    }

    // Module row layout: Generation(2) Name(string_idx) Mvid(guid_idx) EncId(guid_idx) EncBaseId(guid_idx)
    let mvid_idx_offset = layout.module_row_offset + 2 + layout.string_idx_size;
    let mvid_idx = if layout.guid_idx_size == 4 {
        read_u32(data, mvid_idx_offset).ok_or("Cannot read Mvid index")? as usize
    } else {
        read_u16(data, mvid_idx_offset).ok_or("Cannot read Mvid index")? as usize
    };
    if mvid_idx == 0 {
        return Err("Mvid index is 0 (no GUID assigned)".into());
    }

    // #GUID heap is 1-indexed, each entry is 16 bytes.
    let guid_offset = layout.guid_heap_offset + (mvid_idx - 1) * 16;
    if guid_offset + 16 > layout.guid_heap_offset + layout.guid_heap_size {
        return Err("Mvid GUID offset out of #GUID heap bounds".into());
    }

    let n = nonce.to_le_bytes();
    let new_guid = [
        n[0], n[1], n[2], n[3], n[0], n[1], n[2], n[3], n[0], n[1], n[2], n[3], n[0], n[1], n[2],
        n[3],
    ];
    data[guid_offset..guid_offset + 16].copy_from_slice(&new_guid);
    Ok(())
}

/// Overwrite the AssemblyDef Name string in the #Strings heap with a same-length
/// nonce-derived name, returning the patched simple name.
///
/// Defeats the CLR binder's simple-name unification of unsigned
/// (`PublicKeyToken=null`) assemblies across AppDomains. Without strong-naming,
/// the binder of a freshly-created AD will reuse a previously-loaded assembly
/// that shares the same simple name, retaining its static state from the prior
/// `Main()` invocation (and its `Console.Out` redirect from another AD).
/// Bumping `(Build, Revision)` is *not* enough because the host store is
/// queried with `Version=0.0.0.0` regardless of the patched version.
///
/// Strategy: in-place same-length overwrite. The first original byte is kept
/// (so the name remains a valid identifier-style token), the rest is filled
/// with bytes cycled from `format!("{:08x}", nonce)`. Caller should pass a
/// process-unique counter as `nonce`.
///
/// The name is restricted to a single null-terminated entry in the heap so we
/// only mutate bytes the AssemblyDef row actually owns.
pub fn patch_assembly_simple_name(data: &mut [u8], nonce: u32) -> Result<String, String> {
    let layout = parse_metadata_layout(data)?;
    let row_off = layout.assembly_def_row_offset;
    let string_idx_size = layout.string_idx_size;

    // AssemblyDef row: HashAlg(4) Maj(2) Min(2) Build(2) Rev(2) Flags(4) PublicKey(blob_idx) Name(string_idx) ...
    let name_idx_offset = row_off + 16 + layout.blob_idx_size;
    let name_str_idx = if string_idx_size == 4 {
        read_u32(data, name_idx_offset).ok_or("Cannot read Name string index")? as usize
    } else {
        read_u16(data, name_idx_offset).ok_or("Cannot read Name string index")? as usize
    };

    if name_str_idx == 0 || name_str_idx >= layout.strings_heap_size {
        return Err(format!(
            "AssemblyDef.Name string index {} out of range (heap size {})",
            name_str_idx, layout.strings_heap_size
        ));
    }

    let abs_name_offset = layout.strings_heap_offset + name_str_idx;
    let heap_end = layout.strings_heap_offset + layout.strings_heap_size;

    let mut name_end = abs_name_offset;
    while name_end < heap_end && data[name_end] != 0 {
        name_end += 1;
    }
    if name_end >= heap_end {
        return Err("AssemblyDef.Name not null-terminated within #Strings heap".into());
    }
    let original_len = name_end - abs_name_offset;
    if original_len == 0 {
        return Err("AssemblyDef.Name is empty".into());
    }

    // Encode the nonce LSB-first so the *prefix* of the new name varies for
    // every counter — `format!("{:08x}", n)` left-pads with zeros, so the
    // first hex chars are constant for small counters and distinct names
    // would still collide on their leading bytes (which is all that fits
    // when the original name is short).
    let original_first = data[abs_name_offset];
    let nonce_hex: String = format!("{:08x}", nonce).chars().rev().collect();
    let mut new_name = Vec::with_capacity(original_len);
    new_name.push(original_first);
    let mut hex_iter = nonce_hex.bytes().cycle();
    while new_name.len() < original_len {
        new_name.push(hex_iter.next().unwrap());
    }

    data[abs_name_offset..abs_name_offset + original_len].copy_from_slice(&new_name);

    Ok(String::from_utf8_lossy(&new_name).into_owned())
}

/// Result of walking the PE / CLI metadata up to the first `AssemblyDef`
/// row. Holds only byte offsets into the source data so the same helper
/// can drive both read-only identity extraction and in-place patching.
struct MetadataLayout {
    assembly_def_row_offset: usize,
    module_row_offset: usize,
    string_idx_size: usize,
    blob_idx_size: usize,
    guid_idx_size: usize,
    strings_heap_offset: usize,
    strings_heap_size: usize,
    blob_heap_offset: usize,
    blob_heap_size: usize,
    guid_heap_offset: usize,
    guid_heap_size: usize,
}

fn parse_metadata_layout(data: &[u8]) -> Result<MetadataLayout, String> {
    // --- Step 1: DOS header → PE offset ---
    if data.len() < 64 {
        return Err("PE too small for DOS header".into());
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err("Not a PE file (missing MZ signature)".into());
    }
    let pe_offset = read_u32(data, 0x3C).ok_or("Cannot read e_lfanew")? as usize;

    // --- Step 2: PE signature ---
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Err("Invalid PE signature".into());
    }

    // --- Step 3: Optional Header ---
    let coff_offset = pe_offset + 4;
    let _machine = read_u16(data, coff_offset).ok_or("Cannot read Machine")?;
    let num_sections = read_u16(data, coff_offset + 2).ok_or("Cannot read NumSections")? as usize;
    let opt_header_size =
        read_u16(data, coff_offset + 16).ok_or("Cannot read OptHeaderSize")? as usize;
    let opt_offset = coff_offset + 20;

    // Magic: 0x10B = PE32, 0x20B = PE32+
    let magic = read_u16(data, opt_offset).ok_or("Cannot read optional header magic")?;
    let is_pe32_plus = magic == 0x20B;

    // Data directories start offset within optional header
    let data_dir_offset = opt_offset + if is_pe32_plus { 112 } else { 96 };

    // Data directory [14] = CLI header (COM descriptor)
    let clr_dir_offset = data_dir_offset + 14 * 8;
    let clr_rva = read_u32(data, clr_dir_offset).ok_or("Cannot read CLR RVA")?;
    let clr_size = read_u32(data, clr_dir_offset + 4).ok_or("Cannot read CLR size")?;

    if clr_rva == 0 || clr_size == 0 {
        return Err("Not a .NET assembly (no CLR data directory)".into());
    }

    // --- Step 4: Section headers to convert RVA → file offset ---
    let sections_offset = opt_offset + opt_header_size;

    let rva_to_offset = |rva: u32| -> Option<usize> {
        for i in 0..num_sections {
            let sec = sections_offset + i * 40;
            let virt_addr = read_u32(data, sec + 12)?;
            let virt_size = read_u32(data, sec + 16)?;
            let raw_offset = read_u32(data, sec + 20)?;
            if rva >= virt_addr && rva < virt_addr + virt_size {
                return Some((rva - virt_addr + raw_offset) as usize);
            }
        }
        None
    };

    // --- Step 5: CLI header ---
    let clr_offset = rva_to_offset(clr_rva).ok_or("Cannot resolve CLR header RVA")?;
    // CLI header layout: cb(4), MajorRuntime(2), MinorRuntime(2), Metadata RVA(4), Metadata Size(4), ...
    let metadata_rva = read_u32(data, clr_offset + 8).ok_or("Cannot read Metadata RVA")?;
    let _metadata_size = read_u32(data, clr_offset + 12).ok_or("Cannot read Metadata size")?;

    // --- Step 6: Metadata header ---
    let meta_offset = rva_to_offset(metadata_rva).ok_or("Cannot resolve Metadata RVA")?;

    // Metadata signature: 0x424A5342 ("BSJB")
    let sig = read_u32(data, meta_offset).ok_or("Cannot read metadata signature")?;
    if sig != 0x424A5342 {
        return Err(format!("Invalid metadata signature: 0x{:08X}", sig));
    }

    // Version string length at offset 12 (padded to 4 bytes)
    let ver_len = read_u32(data, meta_offset + 12).ok_or("Cannot read version length")? as usize;
    let ver_len_padded = (ver_len + 3) & !3;

    // Streams count at offset 16 + ver_len_padded + 2 (flags)
    let flags_offset = meta_offset + 16 + ver_len_padded;
    // flags (2 bytes) then num streams (2 bytes)
    let num_streams = read_u16(data, flags_offset + 2).ok_or("Cannot read stream count")? as usize;

    // --- Step 7: Locate streams (#~, #Strings, #Blob, #US) ---
    let mut stream_header_offset = flags_offset + 4;
    let mut tables_stream_offset: Option<usize> = None;
    let mut strings_heap: Option<(usize, usize)> = None;
    let mut blob_heap: Option<(usize, usize)> = None;
    let mut guid_heap: Option<(usize, usize)> = None;

    for _ in 0..num_streams {
        let stream_offset =
            read_u32(data, stream_header_offset).ok_or("Cannot read stream offset")? as usize;
        let stream_size =
            read_u32(data, stream_header_offset + 4).ok_or("Cannot read stream size")? as usize;

        // Stream name is a null-terminated string at stream_header_offset + 8, padded to 4 bytes
        let name_start = stream_header_offset + 8;
        let name_end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start + 32);
        let name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");
        let name_padded = ((name_end - name_start + 1) + 3) & !3;

        let abs_offset = meta_offset + stream_offset;

        match name {
            "#~" | "#-" => tables_stream_offset = Some(abs_offset),
            "#Strings" => strings_heap = Some((abs_offset, stream_size)),
            "#Blob" => blob_heap = Some((abs_offset, stream_size)),
            "#GUID" => guid_heap = Some((abs_offset, stream_size)),
            _ => {},
        }

        stream_header_offset = name_start + name_padded;
    }

    let tables_off = tables_stream_offset.ok_or("No #~ stream found")?;
    let (strings_heap_offset, strings_heap_size) =
        strings_heap.ok_or("No #Strings heap found")?;
    let (blob_heap_offset, blob_heap_size) = blob_heap.unwrap_or((0, 0));
    let (guid_heap_offset, guid_heap_size) = guid_heap.unwrap_or((0, 0));

    // --- Step 8: Parse #~ stream header ---
    // Offset 0: Reserved (4)
    // Offset 4: MajorVersion (1)
    // Offset 5: MinorVersion (1)
    // Offset 6: HeapSizes (1) — bit 0 = StringsHeap wide (4 bytes), bit 1 = GUIDheap wide, bit 2 = BlobHeap wide
    // Offset 7: Reserved (1)
    // Offset 8: Valid (8) — bitmask of present tables
    // Offset 16: Sorted (8)
    // Offset 24: row counts (4 bytes each for each present table)

    let heap_sizes = data
        .get(tables_off + 6)
        .copied()
        .ok_or("Cannot read HeapSizes")?;
    let string_idx_size: usize = if heap_sizes & 0x01 != 0 { 4 } else { 2 };
    let guid_idx_size: usize = if heap_sizes & 0x02 != 0 { 4 } else { 2 };
    let blob_idx_size: usize = if heap_sizes & 0x04 != 0 { 4 } else { 2 };

    let valid_mask = {
        let b = data
            .get(tables_off + 8..tables_off + 16)
            .ok_or("Cannot read Valid mask")?;
        u64::from_le_bytes(b.try_into().unwrap())
    };

    // Row counts start at offset 24
    let mut row_counts: [u32; 64] = [0; 64];
    let mut rc_offset = tables_off + 24;
    for bit in 0..64u64 {
        if valid_mask & (1 << bit) != 0 {
            let count = read_u32(data, rc_offset).ok_or("Cannot read row count")?;
            row_counts[bit as usize] = count;
            rc_offset += 4;
        }
    }

    // --- Step 9: Calculate table row sizes and find AssemblyDef (table 0x20 = 32) ---
    const ASSEMBLY_TABLE: usize = 0x20;

    if row_counts[ASSEMBLY_TABLE] == 0 {
        return Err("No AssemblyDef table (not an assembly?)".into());
    }

    // Coded index size: 2 if max referenced table has < 2^(16-tag_bits) rows, else 4.
    let coded_idx_size = |tables: &[usize], tag_bits: u32| -> usize {
        let threshold = 1u32 << (16 - tag_bits);
        if tables.iter().any(|&t| row_counts[t] >= threshold) {
            4
        } else {
            2
        }
    };
    let tbl_idx = |t: usize| -> usize {
        if row_counts[t] >= 65536 {
            4
        } else {
            2
        }
    };

    // Coded index types (II.24.2.6 of ECMA-335)
    let ci_type_def_or_ref = coded_idx_size(&[0x00, 0x01, 0x1B], 2);
    let ci_has_constant = coded_idx_size(&[0x04, 0x08, 0x17], 2);
    let ci_has_cattr = coded_idx_size(
        &[
            0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
            0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B,
        ],
        5,
    );
    let ci_has_field_marshal = coded_idx_size(&[0x04, 0x08], 1);
    let ci_has_decl_security = coded_idx_size(&[0x02, 0x06, 0x20], 2);
    let ci_member_ref_parent = coded_idx_size(&[0x00, 0x01, 0x1A, 0x06, 0x1B], 3);
    let ci_has_semantics = coded_idx_size(&[0x14, 0x17], 1);
    let ci_method_def_or_ref = coded_idx_size(&[0x06, 0x0A], 1);
    let ci_member_forwarded = coded_idx_size(&[0x04, 0x06], 1);
    let ci_cattr_type = coded_idx_size(&[0x06, 0x0A], 3);
    let ci_resolution_scope = coded_idx_size(&[0x00, 0x1A, 0x23, 0x01], 2);

    let row_size: [usize; 0x20] = [
        /* 0x00 Module            */ 2 + string_idx_size + guid_idx_size * 3,
        /* 0x01 TypeRef           */ ci_resolution_scope + string_idx_size * 2,
        /* 0x02 TypeDef           */
        4 + string_idx_size * 2 + ci_type_def_or_ref + tbl_idx(0x04) + tbl_idx(0x06),
        /* 0x03 FieldPtr          */ tbl_idx(0x04),
        /* 0x04 Field             */ 2 + string_idx_size + blob_idx_size,
        /* 0x05 MethodPtr         */ tbl_idx(0x06),
        /* 0x06 Method            */
        4 + 2 + 2 + string_idx_size + blob_idx_size + tbl_idx(0x08),
        /* 0x07 ParamPtr          */ tbl_idx(0x08),
        /* 0x08 Param             */ 2 + 2 + string_idx_size,
        /* 0x09 InterfaceImpl     */ tbl_idx(0x02) + ci_type_def_or_ref,
        /* 0x0A MemberRef         */ ci_member_ref_parent + string_idx_size + blob_idx_size,
        /* 0x0B Constant          */ 2 + ci_has_constant + blob_idx_size,
        /* 0x0C CustomAttribute   */ ci_has_cattr + ci_cattr_type + blob_idx_size,
        /* 0x0D FieldMarshal      */ ci_has_field_marshal + blob_idx_size,
        /* 0x0E DeclSecurity      */ 2 + ci_has_decl_security + blob_idx_size,
        /* 0x0F ClassLayout       */ 2 + 4 + tbl_idx(0x02),
        /* 0x10 FieldLayout       */ 4 + tbl_idx(0x04),
        /* 0x11 StandAloneSig     */ blob_idx_size,
        /* 0x12 EventMap          */ tbl_idx(0x02) + tbl_idx(0x14),
        /* 0x13 EventPtr          */ tbl_idx(0x14),
        /* 0x14 Event             */ 2 + string_idx_size + ci_type_def_or_ref,
        /* 0x15 PropertyMap       */ tbl_idx(0x02) + tbl_idx(0x17),
        /* 0x16 PropertyPtr       */ tbl_idx(0x17),
        /* 0x17 Property          */ 2 + string_idx_size + blob_idx_size,
        /* 0x18 MethodSemantics   */ 2 + tbl_idx(0x06) + ci_has_semantics,
        /* 0x19 MethodImpl        */
        tbl_idx(0x02) + ci_method_def_or_ref + ci_method_def_or_ref,
        /* 0x1A ModuleRef         */ string_idx_size,
        /* 0x1B TypeSpec          */ blob_idx_size,
        /* 0x1C ImplMap           */
        2 + ci_member_forwarded + string_idx_size + tbl_idx(0x1A),
        /* 0x1D FieldRVA          */ 4 + tbl_idx(0x04),
        /* 0x1E ENCLog            */ 4 + 4,
        /* 0x1F ENCMap            */ 4,
    ];

    // Module table (0x00) is always the first table when present and has
    // exactly one row. Capture its offset for Mvid patching.
    let module_row_offset = rc_offset;

    let mut data_off = rc_offset;
    for t in 0..ASSEMBLY_TABLE {
        if valid_mask & (1 << t) != 0 {
            data_off += row_counts[t] as usize * row_size[t];
        }
    }

    Ok(MetadataLayout {
        assembly_def_row_offset: data_off,
        module_row_offset,
        string_idx_size,
        blob_idx_size,
        guid_idx_size,
        strings_heap_offset,
        strings_heap_size,
        blob_heap_offset,
        blob_heap_size,
        guid_heap_offset,
        guid_heap_size,
    })
}

/// Get the public key token from the blob heap.
/// The token is the last 8 bytes of SHA-1(PublicKey), reversed, encoded as lowercase hex.
/// If the blob is empty (index 0 or size 0), returns "null".
fn get_public_key_token(blob: &[u8], blob_idx: usize) -> String {
    if blob.is_empty() || blob_idx == 0 {
        return "null".to_string();
    }

    // Blob heap: each entry is prefixed by a compressed size (1, 2, or 4 bytes)
    if blob_idx >= blob.len() {
        return "null".to_string();
    }

    let (size, data_start) = read_compressed_uint(blob, blob_idx);

    if size == 0 {
        return "null".to_string();
    }

    let key_bytes = match blob.get(data_start..data_start + size) {
        Some(b) => b,
        None => return "null".to_string(),
    };

    // Compute SHA-1 and take last 8 bytes reversed
    let sha1 = sha1_bytes(key_bytes);
    let token = &sha1[sha1.len() - 8..];
    let reversed: Vec<u8> = token.iter().rev().cloned().collect();
    reversed
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Read a compressed unsigned integer from a blob according to ECMA-335 II.23.2
fn read_compressed_uint(buf: &[u8], offset: usize) -> (usize, usize) {
    let b0 = buf[offset] as usize;
    if b0 & 0x80 == 0 {
        (b0, offset + 1)
    } else if b0 & 0xC0 == 0x80 {
        let b1 = buf.get(offset + 1).copied().unwrap_or(0) as usize;
        (((b0 & 0x3F) << 8) | b1, offset + 2)
    } else {
        let b1 = buf.get(offset + 1).copied().unwrap_or(0) as usize;
        let b2 = buf.get(offset + 2).copied().unwrap_or(0) as usize;
        let b3 = buf.get(offset + 3).copied().unwrap_or(0) as usize;
        (
            ((b0 & 0x1F) << 24) | (b1 << 16) | (b2 << 8) | b3,
            offset + 4,
        )
    }
}

/// Minimal SHA-1 implementation (no external crate)
fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Pre-processing: padding
    let orig_len = data.len();
    let bit_len = (orig_len as u64) * 8;

    let padded_len = ((orig_len + 9 + 63) / 64) * 64;
    let mut msg = vec![0u8; padded_len];
    msg[..orig_len].copy_from_slice(data);
    msg[orig_len] = 0x80;
    msg[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

    // Process in 512-bit (64-byte) chunks
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut result = [0u8; 20];
    for i in 0..5 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}
