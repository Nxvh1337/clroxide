#[allow(non_snake_case)]
mod helpers;
mod iappdomain;
mod iassembly;
mod iclrassemblyidentitymanager;
mod iclrmetahost;
mod iclrruntimehost;
mod iclrruntimeinfo;
mod iconstructorinfo;
mod icorruntimehost;
mod ienumunknown;
mod ihostassemblystore;
mod imethodinfo;
mod ipropertyinfo;
mod itype;
mod iunknown;
mod pe_identity;
mod types;

pub use helpers::*;
pub use iappdomain::*;
pub use iassembly::*;
pub use iclrassemblyidentitymanager::*;
pub use iclrmetahost::*;
pub use iclrruntimehost::*;
pub use iclrruntimeinfo::*;
pub use iconstructorinfo::*;
pub use icorruntimehost::*;
pub use ienumunknown::*;
pub use ihostassemblystore::*;
pub use imethodinfo::*;
pub use ipropertyinfo::*;
pub use itype::*;
pub use iunknown::*;
pub use pe_identity::*;
pub use types::*;

pub trait Interface: Sized {
    const IID: GUID;

    fn vtable(&self) -> *const std::ffi::c_void;
}

pub trait Class: Sized {
    const CLSID: GUID;
}
