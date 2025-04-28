# Code Bank
## Package File
```toml
[workspace]
resolver = "2"
members = ["extism-maturin", "manifest", "runtime", "libextism", "convert", "convert-macros"]
exclude = ["kernel"]
[workspace.package]
edition = "2021"
authors = ["The Extism Authors", "oss@extism.org"]
license = "BSD-3-Clause"
homepage = "https://extism.org"
repository = "https://github.com/extism/extism"
version = "0.0.0+replaced-by-ci"
[workspace.dependencies]
extism = { path = "./runtime", version = "0.0.0+replaced-by-ci" }
extism-convert = { path = "./convert", version = "0.0.0+replaced-by-ci" }
extism-convert-macros = { path = "./convert-macros", version = "0.0.0+replaced-by-ci" }
extism-manifest = { path = "./manifest", version = "0.0.0+replaced-by-ci" }
```
## convert/src/encoding.rs
```rust
use crate::*;
use base64::Engine;
/// Base64 conversion
///
/// When using `Base64` with `ToBytes` any type that implement `AsRef<[T]>` may be used as the inner value,
/// but only `Base64<String>` and `Base64<Vec>` may be used with `FromBytes`
///
/// A value wrapped in `Base64` will automatically be encoded/decoded using base64, the inner value should not
/// already be base64 encoded.
#[derive(Debug)]
pub struct Base64<T: AsRef<[u8]>>(pub T); { ... }
/// Protobuf encoding
///
/// Allows for `prost` Protobuf messages to be used as arguments to Extism plugin calls
#[cfg(feature = "prost")]
#[derive(Debug)]
pub struct Prost<T: prost::Message>(pub T); { ... }
/// Protobuf encoding
///
/// Allows for `rust-protobuf` Protobuf messages to be used as arguments to Extism plugin calls
#[cfg(feature = "protobuf")]
pub struct Protobuf<T: protobuf::Message>(pub T); { ... }
/// Raw does no conversion, it just copies the memory directly.
/// Note: This will only work for types that implement [bytemuck::Pod](https://docs.rs/bytemuck/latest/bytemuck/trait.Pod.html)
#[cfg(all(feature = "raw", target_endian = "little"))]
pub struct Raw<'a, T: bytemuck::Pod>(pub &'a T); { ... }
impl ToBytes<'_> for serde_json::Value {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl FromBytesOwned for serde_json::Value {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl<T: AsRef<[u8]>> From<T> for Base64<T> {
    fn from(data: T) -> Self { ... }
}
impl<T: AsRef<[u8]>> ToBytes<'_> for Base64<T> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl FromBytesOwned for Base64<Vec<u8>> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for Base64<String> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
#[cfg(feature = "prost")]
impl<T: prost::Message> From<T> for Prost<T> {
    fn from(data: T) -> Self { ... }
}
#[cfg(feature = "prost")]
impl<T: prost::Message> ToBytes<'_> for Prost<T> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
#[cfg(feature = "prost")]
impl<T: Default + prost::Message> FromBytesOwned for Prost<T> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
#[cfg(feature = "protobuf")]
impl<T: protobuf::Message> ToBytes<'_> for Protobuf<T> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
#[cfg(feature = "protobuf")]
impl<T: Default + protobuf::Message> FromBytesOwned for Protobuf<T> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
#[cfg(all(feature = "raw", target_endian = "little"))]
impl<'a, T: bytemuck::Pod> ToBytes<'a> for Raw<'a, T> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
#[cfg(all(feature = "raw", target_endian = "little"))]
impl<'a, T: bytemuck::Pod> FromBytes<'a> for Raw<'a, T> {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
```
## convert/src/from_bytes.rs
```rust
use crate::*;
pub use extism_convert_macros::FromBytes;
/// `FromBytes` is used to define how a type should be decoded when working with
/// Extism memory. It is used for plugin output and host function input.
///
/// `FromBytes` can be derived by delegating encoding to generic type implementing
/// `FromBytes`, e.g., [`Json`], [`Msgpack`].
///
/// ```
/// use extism_convert::{Json, FromBytes};
/// use serde::Deserialize;
///
/// #[derive(FromBytes, Deserialize, PartialEq, Debug)]
/// #[encoding(Json)]
/// struct Struct {
/// hello: String,
/// }
///
/// assert_eq!(Struct::from_bytes(br#"{"hello":"hi"}"#)?, Struct { hello: "hi".into() });
/// # Ok::<(), extism_convert::Error>(())
/// ```
///
/// Custom encodings can also be used, through new-types with a single generic
/// argument, i.e., `Type<T>(T)`, that implement `FromBytesOwned` for the struct.
///
/// ```
/// use std::str::{self, FromStr};
/// use std::convert::Infallible;
/// use extism_convert::{Error, FromBytes, FromBytesOwned};
///
/// // Custom serialization using `FromStr`
/// struct StringEnc<T>(T);
/// impl<T: FromStr> FromBytesOwned for StringEnc<T> where Error: From<<T as FromStr>::Err> {
/// fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> {
/// Ok(Self(str::from_utf8(data)?.parse()?))
/// }
/// }
///
/// #[derive(FromBytes, PartialEq, Debug)]
/// #[encoding(StringEnc)]
/// struct Struct {
/// hello: String,
/// }
///
/// impl FromStr for Struct {
/// type Err = Infallible;
/// fn from_str(s: &str) -> Result<Self, Infallible> {
/// Ok(Self { hello: s.to_owned() })
/// }
/// }
///
/// assert_eq!(Struct::from_bytes(b"hi")?, Struct { hello: "hi".into() });
/// # Ok::<(), extism_convert::Error>(())
/// ```
pub trait FromBytes { ... }
/// `FromBytesOwned` is similar to [`FromBytes`] but it doesn't borrow from the input slice.
/// [`FromBytes`] is automatically implemented for all types that implement `FromBytesOwned`.
///
/// `FromBytesOwned` can be derived through [`#[derive(FromBytes)]`](FromBytes).
pub trait FromBytesOwned { ... }
impl<'a> FromBytes<'a> for &'a [u8] {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
impl<'a> FromBytes<'a> for &'a str {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
impl<'a, T: FromBytesOwned> FromBytes<'a> for T {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for Box<[u8]> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for Vec<u8> {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for String {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for f64 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for f32 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for i64 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for i32 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for u64 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for u32 {
    fn from_bytes_owned(data: &[u8]) -> Result<Self, Error> { ... }
}
impl FromBytesOwned for () {
    fn from_bytes_owned(_: &[u8]) -> Result<Self, Error> { ... }
}
impl<'a, T: FromBytes<'a>> FromBytes<'a> for std::io::Cursor<T> {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
impl<'a, T: FromBytes<'a>> FromBytes<'a> for Option<T> {
    fn from_bytes(data: &'a [u8]) -> Result<Self, Error> { ... }
}
```
## convert/src/lib.rs
```rust
extern crate self as extism_convert;
pub use anyhow::Error;
pub use encoding::{Base64, Json};
pub use encoding::Msgpack;
pub use encoding::Prost;
pub use encoding::Protobuf;
pub use encoding::Raw;
pub use from_bytes::{FromBytes, FromBytesOwned};
pub use memory_handle::MemoryHandle;
pub use to_bytes::ToBytes;
```
## convert/src/memory_handle.rs
```rust
/// `MemoryHandle` describes where in memory a block of data is stored
/// `MemoryHandle` describes where in memory a block of data is stored
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct MemoryHandle { ... }
impl MemoryHandle {
    /// Create a new `MemoryHandle` from an offset in memory and length
    ///
    /// # Safety
    /// This function is unsafe because the specified memory region may not be valid.
    pub unsafe fn new(offset: u64, length: u64) -> MemoryHandle { ... }
    /// `NULL` equivalent
    pub fn null() -> MemoryHandle { ... }
    /// Get the offset of a memory handle
    pub fn offset(&self) -> u64 { ... }
    /// Get the length of the memory region
    pub fn len(&self) -> usize { ... }
    /// Returns `true` when the length is 0
    pub fn is_empty(&self) -> bool { ... }
}
```
## convert/src/tests.rs
```rust
use crate::*;
```
## convert/src/to_bytes.rs
```rust
use crate::*;
pub use extism_convert_macros::ToBytes;
/// `ToBytes` is used to define how a type should be encoded when working with
/// Extism memory. It is used for plugin input and host function output.
///
/// `ToBytes` can be derived by delegating encoding to generic type implementing
/// `ToBytes`, e.g., [`Json`], [`Msgpack`].
///
/// ```
/// use extism_convert::{Json, ToBytes};
/// use serde::Serialize;
///
/// #[derive(ToBytes, Serialize)]
/// #[encoding(Json)]
/// struct Struct {
/// hello: String,
/// }
///
/// assert_eq!(Struct { hello: "hi".into() }.to_bytes()?, br#"{"hello":"hi"}"#);
/// # Ok::<(), extism_convert::Error>(())
/// ```
///
/// But custom types can also be used, as long as they are new-types with a single
/// generic argument, i.e., `Type<T>(T)`, that implement `ToBytes` for the struct.
///
/// ```
/// use extism_convert::{Error, ToBytes};
///
/// // Custom serialization using `ToString`
/// struct StringEnc<T>(T);
/// impl<T: ToString> ToBytes<'_> for StringEnc<&T> {
/// type Bytes = String;
///
/// fn to_bytes(&self) -> Result<String, Error> {
/// Ok(self.0.to_string())
/// }
/// }
///
/// #[derive(ToBytes)]
/// #[encoding(StringEnc)]
/// struct Struct {
/// hello: String,
/// }
///
/// impl ToString for Struct {
/// fn to_string(&self) -> String {
/// self.hello.clone()
/// }
/// }
///
/// assert_eq!(Struct { hello: "hi".into() }.to_bytes()?, b"hi");
/// # Ok::<(), Error>(())
/// ```
pub trait ToBytes { ... }
impl ToBytes<'_> for () {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for Vec<u8> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for String {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl<'a> ToBytes<'a> for &'a [u8] {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl<'a> ToBytes<'a> for &'a str {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for f64 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for f32 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for i64 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for i32 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for u64 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl ToBytes<'_> for u32 {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl<'a, T: ToBytes<'a>> ToBytes<'a> for &'a T {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
impl<'a, T: ToBytes<'a>> ToBytes<'a> for Option<T> {
    fn to_bytes(&self) -> Result<Self::Bytes, Error> { ... }
}
```
## convert-macros/src/lib.rs
```rust
use std::iter;
use manyhow::{ensure, error_message, manyhow, Result};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote, ToTokens};
use syn::{parse_quote, Attribute, DeriveInput, Path};
#[manyhow]
#[proc_macro_derive(ToBytes, attributes(encoding))]
pub fn to_bytes(
    DeriveInput { ... }
#[manyhow]
#[proc_macro_derive(FromBytes, attributes(encoding))]
pub fn from_bytes(
    DeriveInput { ... }
```
## convert-macros/tests/ui/invalid-encoding.rs
```rust
use extism_convert_macros::ToBytes;
```
## convert-macros/tests/ui.rs
```rust
```
## extism-maturin/build.rs
```rust
use std::borrow::Cow;
```
## extism-maturin/src/extism.c
```cpp
#include "extism.h"
```
## extism-maturin/src/lib.rs
```rust
pub use extism::sdk::*;
```
## kernel/src/bin/extism-runtime.rs
```rust
pub use extism_runtime_kernel::*;
```
## kernel/src/lib.rs
```rust
use core::sync::atomic::*;
/// Returns the number of pages needed for the given number of bytes
pub fn num_pages(nbytes: u64) -> usize { ... }
/// Allocate a block of memory and return the offset
#[no_mangle]
pub unsafe fn alloc(n: u64) -> Handle { ... }
/// Free allocated memory
#[no_mangle]
pub unsafe fn free(p: Handle) { ... }
/// Get the length of an allocated memory block
///
/// Note: this should only be called on memory handles returned
/// by a call to `alloc` - it will return garbage on invalid offsets
#[no_mangle]
pub unsafe fn length_unsafe(p: Handle) -> u64 { ... }
/// Get the length but returns 0 if the offset is not a valid handle.
///
/// Note: this function walks each node in the allocations list, which ensures correctness, but is also
/// slow
#[no_mangle]
pub unsafe fn length(p: Pointer) -> u64 { ... }
/// Load a byte from Extism-managed memory
#[no_mangle]
pub unsafe fn load_u8(p: Pointer) -> u8 { ... }
/// Load a u64 from Extism-managed memory
#[no_mangle]
pub unsafe fn load_u64(p: Pointer) -> u64 { ... }
/// Load a byte from the input data
#[no_mangle]
pub unsafe fn input_load_u8(offset: u64) -> u8 { ... }
/// Load a u64 from the input data
#[no_mangle]
pub unsafe fn input_load_u64(offset: u64) -> u64 { ... }
/// Write a byte in Extism-managed memory
#[no_mangle]
pub unsafe fn store_u8(p: Pointer, x: u8) { ... }
/// Write a u64 in Extism-managed memory
#[no_mangle]
pub unsafe fn store_u64(p: Pointer, x: u64) { ... }
/// Set the range of the input data in memory
/// h must always be a handle so that length works on it
/// len must match length(handle)
/// **Note**: this function takes ownership of the handle passed in
/// the caller should not `free` this value
#[no_mangle]
pub unsafe fn input_set(h: Handle, len: u64) { ... }
/// Set the range of the output data in memory
/// **Note**: this function takes ownership of the handle passed in
/// the caller should not `free` this value
#[no_mangle]
pub unsafe fn output_set(p: Pointer, len: u64) { ... }
/// Get the input length
#[no_mangle]
pub fn input_length() -> u64 { ... }
/// Get the input offset in Exitsm-managed memory
#[no_mangle]
pub fn input_offset() -> Handle { ... }
/// Get the output length
#[no_mangle]
pub fn output_length() -> u64 { ... }
/// Get the output offset in Extism-managed memory
#[no_mangle]
pub unsafe fn output_offset() -> Pointer { ... }
/// Reset the allocator
#[no_mangle]
pub unsafe fn reset() { ... }
/// Set the error message offset, the handle passed to this
/// function should not be freed after this call
/// **Note**: this function takes ownership of the handle passed in
/// the caller should not `free` this value
#[no_mangle]
pub unsafe fn error_set(h: Handle) { ... }
/// Get the error message offset, if it's `0` then no error has been set
#[no_mangle]
pub unsafe fn error_get() -> Handle { ... }
/// Get the position of the allocator, this can be used as an indication of how many bytes are currently in-use
#[no_mangle]
pub unsafe fn memory_bytes() -> u64 { ... }
/// Provides information about the usage status of a `MemoryBlock`
#[repr(u8)]
#[derive(PartialEq)]
pub enum MemoryStatus {
    /// Unused memory that is available b
    Unused = 0,
    /// In-use memory
    Active = 1,
    /// Free memory that is available for re-use
    Free = 2,
}
/// A single `MemoryRoot` exists at the start of the memory to track information about the total
/// size of the allocated memory and the position of the bump allocator.
///
/// The overall layout of the Extism-manged memory is organized like this:
/// |------|-------+---------|-------+--------------|
/// | Root | Block +  Data   | Block +     Data     | ...
/// |------|-------+---------|-------+--------------|
///
/// Where `Root` and `Block` are fixed to the size of the `MemoryRoot` and `MemoryBlock` structs. But
/// the size of `Data` is dependent on the allocation size.
///
/// This means that the offset of a `Block` is the size of `Root` plus the size of all existing `Blocks`
/// including their data.
#[repr(C)]
pub struct MemoryRoot { ... }
/// A `MemoryBlock` contains some metadata about a single allocation
#[repr(C)]
pub struct MemoryBlock { ... }
impl MemoryRoot {
    /// Initialize or load the `MemoryRoot` from the correct position in memory
    pub unsafe fn new() -> &'static mut MemoryRoot { ... }
    /// Resets the position of the allocator and zeroes out all allocations
    pub unsafe fn reset(&mut self) { ... }
    /// Create a new `MemoryBlock`, when `Some(block)` is returned, `block` will contain at least enough room for `length` bytes
    /// but may be as large as `length` + `BLOCK_SPLIT_SIZE` bytes. When `None` is returned the allocation has failed.
    pub unsafe fn alloc(&mut self, length: u64) -> Option<&'static mut MemoryBlock> { ... }
    /// Finds the block at an offset in memory
    pub unsafe fn find_block(&mut self, offs: Pointer) -> Option<&mut MemoryBlock> { ... }
}
impl MemoryBlock {
    /// Get a pointer to the next block
    ///
    /// NOTE: This does no checking to ensure the resulting pointer is valid, the offset
    /// is calculated based on metadata provided by the current block
    #[inline]
    pub unsafe fn next_ptr(&mut self) -> *mut MemoryBlock { ... }
    /// Mark a block as free
    pub fn free(&mut self) { ... }
}
```
## libextism/example.c
```cpp
#include "../runtime/extism.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
void log_handler(const char *line, ExtismSize length) { ... }
void hello_world(ExtismCurrentPlugin *plugin, const ExtismVal *inputs,
                 uint64_t n_inputs, ExtismVal *outputs, uint64_t n_outputs,
                 void *data) { ... }
void free_data(void *x) { ... }
uint8_t *read_file(const char *filename, size_t *len) { ... }
int main(int argc, char *argv[]) { ... }
```
## libextism/src/lib.rs
```rust
pub use extism::sdk::*;
```
## manifest/examples/json_schema.rs
```rust
use extism_manifest::Manifest;
use schemars::schema_for;
```
## manifest/src/lib.rs
```rust
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
/// Configure memory settings
#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct MemoryOptions { ... }
/// Generic HTTP request structure
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HttpRequest { ... }
/// Provides additional metadata about a Webassembly module
#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WasmMetadata { ... }
/// The `Wasm` type specifies how to access a WebAssembly module
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum Wasm {
    /// From disk
    File {
        path: PathBuf,
        #[serde(flatten)]
        meta: WasmMetadata,
    },
    /// From memory
    Data {
        #[serde(with = "wasmdata")]
        #[cfg_attr(feature = "json_schema", schemars(schema_with = "wasmdata_schema"))]
        data: Vec<u8>,
        #[serde(flatten)]
        meta: WasmMetadata,
    },
    /// Via HTTP
    Url {
        #[serde(flatten)]
        req: HttpRequest,
        #[serde(flatten)]
        meta: WasmMetadata,
    },
}
/// The `Manifest` type is used to configure the runtime and specify how to load modules.
#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Manifest { ... }
impl MemoryOptions {
    /// Create an empty `MemoryOptions` value
    pub fn new() -> Self { ... }
    /// Set max pages
    pub fn with_max_pages(mut self, pages: u32) -> Self { ... }
    /// Set max HTTP response size
    pub fn with_max_http_response_bytes(mut self, bytes: u64) -> Self { ... }
    /// Set max size of Extism vars
    pub fn with_max_var_bytes(mut self, bytes: u64) -> Self { ... }
}
impl HttpRequest {
    /// Create a new `HttpRequest` to the given URL
    pub fn new(url: impl Into<String>) -> HttpRequest { ... }
    /// Update the method
    pub fn with_method(mut self, method: impl Into<String>) -> HttpRequest { ... }
    /// Add a header
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> HttpRequest { ... }
}
impl From<HttpRequest> for Wasm {
    fn from(req: HttpRequest) -> Self { ... }
}
impl From<std::path::PathBuf> for Wasm {
    fn from(path: std::path::PathBuf) -> Self { ... }
}
impl From<Vec<u8>> for Wasm {
    fn from(data: Vec<u8>) -> Self { ... }
}
impl Wasm {
    /// Load Wasm from a path
    pub fn file(path: impl AsRef<std::path::Path>) -> Self { ... }
    /// Load Wasm directly from a buffer
    pub fn data(data: impl Into<Vec<u8>>) -> Self { ... }
    /// Load Wasm from a URL
    pub fn url(url: impl Into<String>) -> Self { ... }
    /// Load Wasm from an HTTP request
    pub fn http(req: impl Into<HttpRequest>) -> Self { ... }
    /// Get the metadata
    pub fn meta(&self) -> &WasmMetadata { ... }
    /// Get mutable access to the metadata
    pub fn meta_mut(&mut self) -> &mut WasmMetadata { ... }
    /// Update Wasm module name
    pub fn with_name(mut self, name: impl Into<String>) -> Self { ... }
    /// Update Wasm module hash
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self { ... }
}
impl Manifest {
    /// Create a new manifest
    pub fn new(wasm: impl IntoIterator<Item = impl Into<Wasm>>) -> Manifest { ... }
    pub fn with_wasm(mut self, wasm: impl Into<Wasm>) -> Self { ... }
    /// Disallow HTTP requests to all hosts
    pub fn disallow_all_hosts(mut self) -> Self { ... }
    /// Set memory options
    pub fn with_memory_options(mut self, memory: MemoryOptions) -> Self { ... }
    /// Set MemoryOptions::memory_max
    pub fn with_memory_max(mut self, max: u32) -> Self { ... }
    /// Add a hostname to `allowed_hosts`
    pub fn with_allowed_host(mut self, host: impl Into<String>) -> Self { ... }
    /// Set `allowed_hosts`
    pub fn with_allowed_hosts(mut self, hosts: impl Iterator<Item = String>) -> Self { ... }
    /// Add a path to `allowed_paths`
    pub fn with_allowed_path(mut self, src: String, dest: impl AsRef<Path>) -> Self { ... }
    /// Set `allowed_paths`
    pub fn with_allowed_paths(mut self, paths: impl Iterator<Item = (String, PathBuf)>) -> Self { ... }
    /// Set `config`
    pub fn with_config(
            mut self,
            c: impl Iterator<Item = (impl Into<String>, impl Into<String>)>,
        ) -> Self { ... }
    /// Set a single `config` key
    pub fn with_config_key(mut self, k: impl Into<String>, v: impl Into<String>) -> Self { ... }
    /// Set `timeout_ms`, which will interrupt a plugin function's execution if it meets or
    /// exceeds this value. When an interrupt is made, the plugin will not be able to recover and
    /// continue execution.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self { ... }
}
impl From<Manifest> for std::borrow::Cow<'_, [u8]> {
    fn from(m: Manifest) -> Self { ... }
}
impl From<&Manifest> for std::borrow::Cow<'_, [u8]> {
    fn from(m: &Manifest) -> Self { ... }
}
```
## runtime/benches/bench.rs
```rust
use criterion::{criterion_group, criterion_main, Criterion};
use extism::*;
use extism_convert::Json;
pub fn basic(c: &mut Criterion) { ... }
pub fn create_plugin(c: &mut Criterion) { ... }
pub fn create_compiled(c: &mut Criterion) { ... }
pub fn create_plugin_compiled(c: &mut Criterion) { ... }
pub fn create_plugin_no_cache(c: &mut Criterion) { ... }
pub fn count_vowels(c: &mut Criterion) { ... }
pub fn consume(c: &mut Criterion) { ... }
pub fn echo(c: &mut Criterion) { ... }
pub fn reflect(c: &mut Criterion) { ... }
pub fn allocations(c: &mut Criterion) { ... }
pub fn reflect_linked(c: &mut Criterion) { ... }
```
## runtime/build.rs
```rust
```
## runtime/examples/fs.rs
```rust
use extism::*;
```
## runtime/examples/linking.rs
```rust
use extism::*;
```
## runtime/examples/log_callback.rs
```rust
use extism::*;
```
## runtime/examples/readme.rs
```rust
use extism::*;
```
## runtime/extism.h
```cpp
#include <stdint.h>
#include <stdbool.h>
#define EXTISM_FUNCTION(N) extern void N(ExtismCurrentPlugin*, const ExtismVal*, ExtismSize, ExtismVal*, ExtismSize, void*)
#define EXTISM_GO_FUNCTION(N) extern void N(void*, ExtismVal*, ExtismSize, ExtismVal*, ExtismSize, uintptr_t)
#define EXTISM_SUCCESS 0
#define EXTISM_PTR ExtismValType_I64
```
## runtime/src/current_plugin.rs
```rust
use anyhow::Context;
use crate::*;
/// CurrentPlugin stores data that is available to the caller in PDK functions, this should
/// only be accessed from inside a host function
pub struct CurrentPlugin { ... }
unsafe impl Send for CurrentPlugin {
}
impl wasmtime::ResourceLimiter for MemoryLimiter {
    fn memory_growing(
            &mut self,
            current: usize,
            desired: usize,
            maximum: Option<usize>,
        ) -> Result<bool> { ... }
    fn table_growing(
            &mut self,
            _current: usize,
            desired: usize,
            maximum: Option<usize>,
        ) -> Result<bool> { ... }
}
impl CurrentPlugin {
    /// Gets `Plugin`'s ID
    pub fn id(&self) -> uuid::Uuid { ... }
    /// Get a `MemoryHandle` from a memory offset
    pub fn memory_handle(&mut self, offs: u64) -> Option<MemoryHandle> { ... }
    /// Access memory bytes as `str`
    pub fn memory_str_mut(&mut self, handle: MemoryHandle) -> Result<&mut str, Error> { ... }
    pub fn memory_str(&mut self, handle: MemoryHandle) -> Result<&str, Error> { ... }
    /// Allocate a handle large enough for the encoded Rust type and copy it into Extism memory
    pub fn memory_new<'a, T: ToBytes<'a>>(&mut self, t: T) -> Result<MemoryHandle, Error> { ... }
    /// Decode a Rust type from Extism memory
    pub fn memory_get<'a, T: FromBytes<'a>>(
            &'a mut self,
            handle: MemoryHandle,
        ) -> Result<T, Error> { ... }
    /// Decode a Rust type from Extism memory from an offset in memory specified by a `Val`
    pub fn memory_get_val<'a, T: FromBytes<'a>>(&'a mut self, offs: &Val) -> Result<T, Error> { ... }
    /// Encode a Rust type into Extism memory and store it in the given `Val`, this can be used to return
    /// values from host functions.
    pub fn memory_set_val<'a, T: ToBytes<'a>>(
            &'a mut self,
            offs: &mut Val,
            data: T,
        ) -> Result<(), Error> { ... }
    pub fn memory_bytes_mut(&mut self, handle: MemoryHandle) -> Result<&mut [u8], Error> { ... }
    pub fn memory_bytes(&mut self, handle: MemoryHandle) -> Result<&[u8], Error> { ... }
    pub fn host_context<T: 'static>(&mut self) -> Result<&mut T, Error> { ... }
    pub fn memory_alloc(&mut self, n: u64) -> Result<MemoryHandle, Error> { ... }
    /// Free a block of Extism plugin memory
    pub fn memory_free(&mut self, handle: MemoryHandle) -> Result<(), Error> { ... }
    pub fn memory_length(&mut self, offs: u64) -> Result<u64, Error> { ... }
    pub fn memory_length_unsafe(&mut self, offs: u64) -> Result<u64, Error> { ... }
    /// Access a plugin's variables
    pub fn vars(&self) -> &std::collections::BTreeMap<String, Vec<u8>> { ... }
    /// Mutable access to a plugin's variables
    pub fn vars_mut(&mut self) -> &mut std::collections::BTreeMap<String, Vec<u8>> { ... }
    /// Plugin manifest
    pub fn manifest(&self) -> &Manifest { ... }
    /// Get a `MemoryHandle` from a `Val` reference - this can be used to convert a host function's
    /// argument directly to `MemoryHandle`
    pub fn memory_from_val(&mut self, offs: &Val) -> Option<MemoryHandle> { ... }
    /// Get a `MemoryHandle` from a `Val` reference - this can be used to convert a host function's
    /// argument directly to `MemoryHandle`
    pub fn memory_to_val(&mut self, handle: MemoryHandle) -> Val { ... }
    /// Clear the current plugin error
    pub fn clear_error(&mut self) { ... }
    /// Get the current error message
    pub fn get_error(&mut self) -> Option<&str> { ... }
    #[doc(hidden)]
    pub fn set_error(&mut self, s: impl AsRef<str>) -> Result<(u64, u64), Error> { ... }
    /// Returns the remaining time before a plugin will timeout, or
    /// `None` if no timeout is configured in the manifest
    pub fn time_remaining(&self) -> Option<std::time::Duration> { ... }
}
impl Internal for CurrentPlugin {
    fn store(&self) -> &Store<CurrentPlugin> { ... }
    fn store_mut(&mut self) -> &mut Store<CurrentPlugin> { ... }
    fn linker_and_store(&mut self) -> (&mut Linker<CurrentPlugin>, &mut Store<CurrentPlugin>) { ... }
}
```
## runtime/src/function.rs
```rust
use std::sync::Arc;
use wasmtime::Caller;
use crate::{error, trace, CurrentPlugin, Error};
/// An enumeration of all possible value types in WebAssembly.
/// cbindgen:prefix-with-name
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[repr(C)]
pub enum ValType {
    // NB: the ordering here is intended to match the ordering in
    // `wasmtime_types::WasmType` to help improve codegen when converting.
    /// Signed 32 bit integer.
    I32,
    /// Signed 64 bit integer.
    I64,
    /// Floating point 32 bit integer.
    F32,
    /// Floating point 64 bit integer.
    F64,
    /// A 128 bit number.
    V128,
    /// A reference to a Wasm function.
    FuncRef,
    /// A reference to opaque data in the Wasm instance.
    ExternRef,
}
/// A pointer to C userdata
#[derive(Debug)]
pub struct CPtr { ... }
/// UserData is used to store additional data that gets passed into host function callbacks
///
/// `UserData` is used to store `C` and `Rust` data from hosts. The Rust data in wrapped in an `Arc<Mutex<T>>` and can be accessed
/// using `UserData::get`. The `C` data is stored as a pointer and cleanup function and isn't usable from Rust. The cleanup function
/// will be called when the inner `CPtr` is dropped.
#[derive(Debug)]
pub enum UserData<T: Sized> {
    C(Arc<CPtr>),
    Rust(Arc<std::sync::Mutex<T>>),
}
/// Wraps raw host functions with some additional metadata and user data
#[derive(Clone)]
pub struct Function { ... }
impl From<wasmtime::ValType> for ValType {
    fn from(value: wasmtime::ValType) -> Self { ... }
}
impl From<ValType> for wasmtime::ValType {
    fn from(value: ValType) -> Self { ... }
}
impl<T: Default> Default for UserData<T> {
    fn default() -> Self { ... }
}
impl<T> Clone for UserData<T> {
    fn clone(&self) -> Self { ... }
}
impl<T> UserData<T> {
    /// Create a new `UserData` from a Rust value
    ///
    /// This will wrap the provided value in a reference-counted mutex
    pub fn new(x: T) -> Self { ... }
    /// Get a copy of the inner value
    pub fn get(&self) -> Result<Arc<std::sync::Mutex<T>>, Error> { ... }
}
impl Drop for CPtr {
    fn drop(&mut self) { ... }
}
unsafe impl<T> Send for UserData<T> {
}
unsafe impl<T> Sync for UserData<T> {
}
unsafe impl Send for CPtr {
}
unsafe impl Sync for CPtr {
}
impl Function {
    /// Create a new host function
    pub fn new<T: 'static, F>(
            name: impl Into<String>,
            params: impl IntoIterator<Item = ValType>,
            results: impl IntoIterator<Item = ValType>,
            user_data: UserData<T>,
            f: F,
        ) -> Function
        where
            F: 'static
                + Fn(&mut CurrentPlugin, &[Val], &mut [Val], UserData<T>) -> Result<(), Error>
                + Sync
                + Send, { ... }
    /// Host function name
    pub fn name(&self) -> &str { ... }
    /// Host function module name
    pub fn namespace(&self) -> Option<&str> { ... }
    /// Set host function module name
    pub fn set_namespace(&mut self, namespace: impl Into<String>) { ... }
    /// Update host function module name
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self { ... }
    /// Get param types
    pub fn params(&self) -> &[ValType] { ... }
    /// Get result types
    pub fn results(&self) -> &[ValType] { ... }
}
```
## runtime/src/internal.rs
```rust
use crate::*;
/// WASI context
pub struct Wasi { ... }
```
## runtime/src/lib.rs
```rust
extern crate self as extism;
pub(crate) use extism_convert::*;
pub(crate) use std::collections::BTreeMap;
use std::str::FromStr;
pub(crate) use wasmtime::*;
pub use extism_convert as convert;
pub use anyhow::Error;
pub use current_plugin::CurrentPlugin;
pub use extism_convert::{FromBytes, FromBytesOwned, ToBytes};
pub use extism_manifest::{Manifest, Wasm, WasmMetadata};
pub use function::{Function, UserData, Val, ValType, PTR};
pub use plugin::{
    CancelHandle, CompiledPlugin, Plugin, WasmInput, EXTISM_ENV_MODULE, EXTISM_USER_MODULE,
};
pub use plugin_builder::{DebugOptions, PluginBuilder};
pub(crate) use internal::{Internal, Wasi};
pub(crate) use timer::{Timer, TimerAction};
pub(crate) use tracing::{debug, error, trace, warn};
/// Extism C API
pub mod sdk {
}
/// Returns a string containing the Extism version of the current runtime, this is the same as the Cargo package
/// version
pub fn extism_version() -> &'static str { ... }
/// Sets a custom callback to handle logs, each line will be passed to the provided callback instead of being
/// logged to a file. This initializes a default `tracing_subscriber` and should only be called once.
///
/// `filter` may contain a general level like `trace` or `error`, but can also be more specific to enable logging only
/// from specific crates. For example, to enable trace-level logging only for the extism crate use: `extism=trace`.
pub fn set_log_callback<F: 'static + Clone + Fn(&str)>(
    func: F,
    filter: impl AsRef<str>,
) -> Result<(), Error> { ... }
unsafe impl<F: Clone + Fn(&str)> Send for LogFunction<F> {
}
unsafe impl<F: Clone + Fn(&str)> Sync for LogFunction<F> {
}
impl<F: Clone + Fn(&str)> std::io::Write for LogFunction<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { ... }
    fn flush(&mut self) -> std::io::Result<()> { ... }
}
```
## runtime/src/manifest.rs
```rust
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::io::Read;
use sha2::Digest;
use crate::plugin::{WasmInput, MAIN_KEY};
use crate::*;
```
## runtime/src/pdk.rs
```rust
/// All the functions in the file are exposed from inside WASM plugins
use crate::*;
pub fn log(
    level: tracing::Level,
    mut caller: Caller<CurrentPlugin>,
    input: &[Val],
    _output: &mut [Val],
) -> Result<(), Error> { ... }
```
## runtime/src/plugin.rs
```rust
use std::{
    any::Any,
    collections::{BTreeMap, BTreeSet},
    sync::TryLockError,
};
use anyhow::Context;
use plugin_builder::PluginBuilderOptions;
use crate::*;
/// A `CancelHandle` can be used to cancel a running plugin from another thread
#[derive(Clone)]
pub struct CancelHandle { ... }
#[derive(Clone)]
pub struct CompiledPlugin { ... }
/// Plugin contains everything needed to execute a WASM function
pub struct Plugin { ... }
/// Defines an input type for Wasm data.
///
/// Types that implement `Into<WasmInput>` can be passed directly into `Plugin::new`
pub enum WasmInput<'a> {
    /// Raw Wasm module
    Data(std::borrow::Cow<'a, [u8]>),
    /// Owned manifest
    Manifest(Manifest),
    /// Borrowed manifest
    ManifestRef(&'a Manifest),
}
unsafe impl Sync for CancelHandle {
}
unsafe impl Send for CancelHandle {
}
impl CancelHandle {
    pub fn cancel(&self) -> Result<(), Error> { ... }
}
impl CompiledPlugin {
    /// Create a new pre-compiled plugin
    pub fn new(builder: PluginBuilder) -> Result<CompiledPlugin, Error> { ... }
}
unsafe impl Send for Plugin {
}
unsafe impl Sync for Plugin {
}
impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { ... }
}
impl Internal for Plugin {
    fn store(&self) -> &Store<CurrentPlugin> { ... }
    fn store_mut(&mut self) -> &mut Store<CurrentPlugin> { ... }
    fn linker_and_store(&mut self) -> (&mut Linker<CurrentPlugin>, &mut Store<CurrentPlugin>) { ... }
}
impl From<Manifest> for WasmInput<'_> {
    fn from(value: Manifest) -> Self { ... }
}
impl<'a> From<&'a Manifest> for WasmInput<'a> {
    fn from(value: &'a Manifest) -> Self { ... }
}
impl<'a> From<&'a mut Manifest> for WasmInput<'a> {
    fn from(value: &'a mut Manifest) -> Self { ... }
}
impl<'a> From<&'a [u8]> for WasmInput<'a> {
    fn from(value: &'a [u8]) -> Self { ... }
}
impl<'a> From<&'a str> for WasmInput<'a> {
    fn from(value: &'a str) -> Self { ... }
}
impl From<Vec<u8>> for WasmInput<'_> {
    fn from(value: Vec<u8>) -> Self { ... }
}
impl<'a> From<&'a Vec<u8>> for WasmInput<'a> {
    fn from(value: &'a Vec<u8>) -> Self { ... }
}
impl Plugin {
    /// Create a new plugin from a Manifest or WebAssembly module, and host functions. The `with_wasi`
    /// parameter determines whether or not the module should be executed with WASI enabled.
    pub fn new<'a>(
            wasm: impl Into<WasmInput<'a>>,
            imports: impl IntoIterator<Item = Function>,
            with_wasi: bool,
        ) -> Result<Plugin, Error> { ... }
    /// Create a new plugin from a pre-compiled plugin
    pub fn new_from_compiled(compiled: &CompiledPlugin) -> Result<Plugin, Error> { ... }
    /// Returns `true` if the given function exists, otherwise `false`
    pub fn function_exists(&self, function: impl AsRef<str>) -> bool { ... }
    /// Reset Extism runtime, this will invalidate all allocated memory
    pub fn reset(&mut self) -> Result<(), Error> { ... }
    /// Determine if wasi is enabled
    pub fn has_wasi(&self) -> bool { ... }
    /// Call a function by name with the given input, the return value is
    /// the output data returned by the plugin. The return type can be anything that implements
    /// [FromBytes]. This data will be invalidated next time the plugin is called.
    ///
    /// # Arguments
    ///
    /// * `name` - A string representing the name of the export function to call
    /// * `input` - The input argument to the function. Type should implment [ToBytes].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // call takes a ToBytes and FromBytes type
    /// // this function takes an &str and returns an &str
    /// let output = plugin.call::<&str, &str>("greet", "Benjamin")?;
    /// assert_eq!(output, "Hello, Benjamin!");
    /// ```
    pub fn call<'a, 'b, T: ToBytes<'a>, U: FromBytes<'b>>(
            &'b mut self,
            name: impl AsRef<str>,
            input: T,
        ) -> Result<U, Error> { ... }
    pub fn call_with_host_context<'a, 'b, T, U, C>(
            &'b mut self,
            name: impl AsRef<str>,
            input: T,
            host_context: C,
        ) -> Result<U, Error>
        where
            T: ToBytes<'a>,
            U: FromBytes<'b>,
            C: Any + Send + Sync + 'static, { ... }
    /// Similar to `Plugin::call`, but returns the Extism error code along with the
    /// `Error`. It is assumed if `Ok(_)` is returned that the error code was `0`.
    ///
    /// All Extism plugin calls return an error code, `Plugin::call` consumes the error code,
    /// while `Plugin::call_get_error_code` preserves it - this function should only be used
    /// when you need to inspect the actual return value of a plugin function when it fails.
    pub fn call_get_error_code<'a, 'b, T: ToBytes<'a>, U: FromBytes<'b>>(
            &'b mut self,
            name: impl AsRef<str>,
            input: T,
        ) -> Result<U, (Error, i32)> { ... }
    /// Get a `CancelHandle`, which can be used from another thread to cancel a running plugin
    pub fn cancel_handle(&self) -> CancelHandle { ... }
    /// Returns the amount of fuel consumed by the plugin.
    ///
    /// This function calculates the difference between the initial fuel and the remaining fuel.
    /// If either the initial fuel or the remaining fuel is not set, it returns `None`.
    ///
    /// # Returns
    ///
    /// * `Some(u64)` - The amount of fuel consumed.
    /// * `None` - If the initial fuel or remaining fuel is not set.
    pub fn fuel_consumed(&self) -> Option<u64> { ... }
}
```
## runtime/src/plugin_builder.rs
```rust
use std::path::PathBuf;
use crate::{plugin::WasmInput, *};
#[derive(Clone)]
pub struct DebugOptions { ... }
/// PluginBuilder is used to configure and create `Plugin` instances
pub struct PluginBuilder<'a> { ... }
impl Default for DebugOptions {
    fn default() -> Self { ... }
}
impl<'a> PluginBuilder<'a> {
    /// Create a new `PluginBuilder` from a `Manifest` or raw Wasm bytes
    pub fn new(plugin: impl Into<WasmInput<'a>>) -> Self { ... }
    /// Enables WASI if the argument is set to `true`
    pub fn with_wasi(mut self, wasi: bool) -> Self { ... }
    /// Add a single host function
    pub fn with_function<T: 'static, F>(
            mut self,
            name: impl Into<String>,
            args: impl IntoIterator<Item = ValType>,
            returns: impl IntoIterator<Item = ValType>,
            user_data: UserData<T>,
            f: F,
        ) -> Self
        where
            F: 'static
                + Fn(&mut CurrentPlugin, &[Val], &mut [Val], UserData<T>) -> Result<(), Error>
                + Sync
                + Send, { ... }
    /// Add a single host function in a specific namespace
    pub fn with_function_in_namespace<T: 'static, F>(
            mut self,
            namespace: impl Into<String>,
            name: impl Into<String>,
            args: impl IntoIterator<Item = ValType>,
            returns: impl IntoIterator<Item = ValType>,
            user_data: UserData<T>,
            f: F,
        ) -> Self
        where
            F: 'static
                + Fn(&mut CurrentPlugin, &[Val], &mut [Val], UserData<T>) -> Result<(), Error>
                + Sync
                + Send, { ... }
    /// Add multiple host functions
    pub fn with_functions(mut self, f: impl IntoIterator<Item = Function>) -> Self { ... }
    /// Set profiling strategy
    pub fn with_profiling_strategy(mut self, p: wasmtime::ProfilingStrategy) -> Self { ... }
    /// Enable Wasmtime coredump on trap
    pub fn with_coredump(mut self, path: impl Into<std::path::PathBuf>) -> Self { ... }
    /// Enable Extism memory dump when plugin calls return an error
    pub fn with_memdump(mut self, path: impl Into<std::path::PathBuf>) -> Self { ... }
    /// Compile with debug info
    pub fn with_debug_info(mut self) -> Self { ... }
    /// Configure debug options
    pub fn with_debug_options(mut self, options: DebugOptions) -> Self { ... }
    /// Set wasmtime compilation cache config path
    pub fn with_cache_config(mut self, dir: impl Into<PathBuf>) -> Self { ... }
    /// Turn wasmtime compilation caching off
    pub fn with_cache_disabled(mut self) -> Self { ... }
    /// Limit the number of instructions that can be executed
    pub fn with_fuel_limit(mut self, fuel: u64) -> Self { ... }
    /// Configure an initial wasmtime config to be passed to the plugin
    ///
    /// **Warning**: some values might be overwritten by the Extism runtime. In particular:
    /// - async_support
    /// - epoch_interruption
    /// - debug_info
    /// - coredump_on_trap
    /// - profiler
    /// - wasm_tail_call
    /// - wasm_function_references
    /// - wasm_gc
    ///
    /// See the implementation details of [PluginBuilder::build] and [Plugin::build_new] to verify which values are overwritten.
    pub fn with_wasmtime_config(mut self, config: wasmtime::Config) -> Self { ... }
    /// Enables `http_response_headers`, which allows for plugins to access response headers when using `extism:host/env::http_request`
    pub fn with_http_response_headers(mut self, allow: bool) -> Self { ... }
    /// Generate a new plugin with the configured settings
    pub fn build(self) -> Result<Plugin, Error> { ... }
    /// Build new `CompiledPlugin`
    pub fn compile(self) -> Result<CompiledPlugin, Error> { ... }
}
```
## runtime/src/readonly_dir.rs
```rust
use crate::*;
use wasi_common::{Error, ErrorExt};
pub struct ReadOnlyDir<D: wasi_common::WasiDir> { ... }
impl<D: wasi_common::WasiDir> ReadOnlyDir<D> {
    pub fn new(inner: D) -> Self { ... }
}
#[wiggle::async_trait]
impl<D: wasi_common::WasiDir> wasi_common::WasiDir for ReadOnlyDir<D> {
    fn as_any(&self) -> &dyn std::any::Any { ... }
    async fn open_file(
            &self,
            symlink_follow: bool,
            path: &str,
            oflags: wasi_common::file::OFlags,
            read: bool,
            write: bool,
            fdflags: wasi_common::file::FdFlags,
        ) -> Result<wasi_common::dir::OpenResult, Error> { ... }
    async fn create_dir(&self, _path: &str) -> Result<(), Error> { ... }
    async fn readdir(
            &self,
            cursor: wasi_common::dir::ReaddirCursor,
        ) -> Result<
            Box<dyn Iterator<Item = Result<wasi_common::dir::ReaddirEntity, Error>> + Send>,
            Error,
        > { ... }
    async fn symlink(&self, _old_path: &str, _new_path: &str) -> Result<(), Error> { ... }
    async fn remove_dir(&self, _path: &str) -> Result<(), Error> { ... }
    async fn unlink_file(&self, _path: &str) -> Result<(), Error> { ... }
    async fn read_link(&self, path: &str) -> Result<std::path::PathBuf, Error> { ... }
    async fn get_filestat(&self) -> Result<wasi_common::file::Filestat, Error> { ... }
    async fn get_path_filestat(
            &self,
            path: &str,
            follow_symlinks: bool,
        ) -> Result<wasi_common::file::Filestat, Error> { ... }
    async fn rename(
            &self,
            _path: &str,
            _dest_dir: &dyn wasi_common::WasiDir,
            _dest_path: &str,
        ) -> Result<(), Error> { ... }
    async fn hard_link(
            &self,
            _path: &str,
            _target_dir: &dyn wasi_common::WasiDir,
            _target_path: &str,
        ) -> Result<(), Error> { ... }
    async fn set_times(
            &self,
            _path: &str,
            _atime: std::option::Option<wasi_common::SystemTimeSpec>,
            _mtime: std::option::Option<wasi_common::SystemTimeSpec>,
            _follow_symlinks: bool,
        ) -> Result<(), Error> { ... }
}
```
## runtime/src/sdk.rs
```rust
use std::{os::raw::c_char, ptr::null_mut};
use crate::*;
/// Get a plugin's ID, the returned bytes are a 16 byte buffer that represent a UUIDv4
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_id(plugin: *mut Plugin) -> *const u8 { ... }
/// Get the current plugin's associated host context data. Returns null if call was made without
/// host context.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_host_context(
    plugin: *mut CurrentPlugin,
) -> *mut std::ffi::c_void { ... }
/// Returns a pointer to the memory of the currently running plugin
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory(plugin: *mut CurrentPlugin) -> *mut u8 { ... }
/// Allocate a memory block in the currently running plugin
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory_alloc(
    plugin: *mut CurrentPlugin,
    n: Size,
) -> ExtismMemoryHandle { ... }
/// Get the length of an allocated block
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory_length(
    plugin: *mut CurrentPlugin,
    n: ExtismMemoryHandle,
) -> Size { ... }
/// Free an allocated memory block
/// NOTE: this should only be called from host functions.
#[no_mangle]
pub unsafe extern "C" fn extism_current_plugin_memory_free(
    plugin: *mut CurrentPlugin,
    ptr: ExtismMemoryHandle,
) { ... }
/// Create a new host function
///
/// Arguments
/// - `name`: function name, this should be valid UTF-8
/// - `inputs`: argument types
/// - `n_inputs`: number of argument types
/// - `outputs`: return types
/// - `n_outputs`: number of return types
/// - `func`: the function to call
/// - `user_data`: a pointer that will be passed to the function when it's called
/// this value should live as long as the function exists
/// - `free_user_data`: a callback to release the `user_data` value when the resulting
/// `ExtismFunction` is freed.
///
/// Returns a new `ExtismFunction` or `null` if the `name` argument is invalid.
#[no_mangle]
pub unsafe extern "C" fn extism_function_new(
    name: *const std::ffi::c_char,
    inputs: *const ValType,
    n_inputs: Size,
    outputs: *const ValType,
    n_outputs: Size,
    func: ExtismFunctionType,
    user_data: *mut std::ffi::c_void,
    free_user_data: Option<extern "C" fn(_: *mut std::ffi::c_void)>,
) -> *mut ExtismFunction { ... }
/// Free `ExtismFunction`
#[no_mangle]
pub unsafe extern "C" fn extism_function_free(f: *mut ExtismFunction) { ... }
/// Set the namespace of an `ExtismFunction`
#[no_mangle]
pub unsafe extern "C" fn extism_function_set_namespace(
    ptr: *mut ExtismFunction,
    namespace: *const std::ffi::c_char,
) { ... }
/// Pre-compile an Extism plugin
#[no_mangle]
pub unsafe extern "C" fn extism_compiled_plugin_new(
    wasm: *const u8,
    wasm_size: Size,
    functions: *mut *const ExtismFunction,
    n_functions: Size,
    with_wasi: bool,
    errmsg: *mut *mut std::ffi::c_char,
) -> *mut CompiledPlugin { ... }
/// Free `ExtismCompiledPlugin`
#[no_mangle]
pub unsafe extern "C" fn extism_compiled_plugin_free(plugin: *mut CompiledPlugin) { ... }
/// Create a new plugin with host functions, the functions passed to this function no longer need to be manually freed using
///
/// `wasm`: is a WASM module (wat or wasm) or a JSON encoded manifest
/// `wasm_size`: the length of the `wasm` parameter
/// `functions`: an array of `ExtismFunction*`
/// `n_functions`: the number of functions provided
/// `with_wasi`: enables/disables WASI
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new(
    wasm: *const u8,
    wasm_size: Size,
    functions: *mut *const ExtismFunction,
    n_functions: Size,
    with_wasi: bool,
    errmsg: *mut *mut std::ffi::c_char,
) -> *mut Plugin { ... }
/// Create a new plugin from an `ExtismCompiledPlugin`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new_from_compiled(
    compiled: *const CompiledPlugin,
    errmsg: *mut *mut std::ffi::c_char,
) -> *mut Plugin { ... }
/// Create a new plugin and set the number of instructions a plugin is allowed to execute
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new_with_fuel_limit(
    wasm: *const u8,
    wasm_size: Size,
    functions: *mut *const ExtismFunction,
    n_functions: Size,
    with_wasi: bool,
    fuel_limit: u64,
    errmsg: *mut *mut std::ffi::c_char,
) -> *mut Plugin { ... }
/// Enable HTTP response headers in plugins using `extism:host/env::http_request`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_allow_http_response_headers(plugin: *mut Plugin) { ... }
/// Free the error returned by `extism_plugin_new`, errors returned from `extism_plugin_error` don't need to be freed
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_new_error_free(err: *mut std::ffi::c_char) { ... }
/// Free `ExtismPlugin`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_free(plugin: *mut Plugin) { ... }
/// Get handle for plugin cancellation
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_cancel_handle(plugin: *const Plugin) -> *const CancelHandle { ... }
/// Cancel a running plugin
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_cancel(handle: *const CancelHandle) -> bool { ... }
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_config(
    plugin: *mut Plugin,
    json: *const u8,
    json_size: Size,
) -> bool { ... }
/// Returns true if `func_name` exists
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_function_exists(
    plugin: *mut Plugin,
    func_name: *const c_char,
) -> bool { ... }
/// Call a function
///
/// `func_name`: is the function to call
/// `data`: is the input data
/// `data_len`: is the length of `data`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_call(
    plugin: *mut Plugin,
    func_name: *const c_char,
    data: *const u8,
    data_len: Size,
) -> i32 { ... }
/// Call a function with host context.
///
/// `func_name`: is the function to call
/// `data`: is the input data
/// `data_len`: is the length of `data`
/// `host_context`: a pointer to context data that will be available in host functions
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_call_with_host_context(
    plugin: *mut Plugin,
    func_name: *const c_char,
    data: *const u8,
    data_len: Size,
    host_context: *mut std::ffi::c_void,
) -> i32 { ... }
/// Get the error associated with a `Plugin`
#[no_mangle]
#[deprecated]
pub unsafe extern "C" fn extism_error(plugin: *mut Plugin) -> *const c_char { ... }
/// Get the error associated with a `Plugin`
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_error(plugin: *mut Plugin) -> *const c_char { ... }
/// Get the length of a plugin's output data
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_output_length(plugin: *mut Plugin) -> Size { ... }
/// Get a pointer to the output data
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_output_data(plugin: *mut Plugin) -> *const u8 { ... }
/// Set log file and level.
/// The log level can be either one of: info, error, trace, debug, warn or a more
/// complex filter like `extism=trace,cranelift=debug`
/// The file will be created if it doesn't exist.
#[no_mangle]
pub unsafe extern "C" fn extism_log_file(
    filename: *const c_char,
    log_level: *const c_char,
) -> bool { ... }
/// Enable a custom log handler, this will buffer logs until `extism_log_drain` is called
/// Log level should be one of: info, error, trace, debug, warn
#[no_mangle]
pub unsafe extern "C" fn extism_log_custom(log_level: *const c_char) -> bool { ... }
/// Calls the provided callback function for each buffered log line.
/// This is only needed when `extism_log_custom` is used.
pub unsafe extern "C" fn extism_log_drain(handler: ExtismLogDrainFunctionType) { ... }
/// Reset the Extism runtime, this will invalidate all allocated memory
#[no_mangle]
pub unsafe extern "C" fn extism_plugin_reset(plugin: *mut Plugin) -> bool { ... }
/// Get the Extism version string
#[no_mangle]
pub unsafe extern "C" fn extism_version() -> *const c_char { ... }
pub struct ExtismFunction(std::cell::Cell<Option<Function>>); { ... }
/// `ExtismVal` holds the type and value of a function argument/return
#[repr(C)]
pub struct ExtismVal { ... }
unsafe impl Send for CVoidContainer {
}
unsafe impl Sync for CVoidContainer {
}
unsafe impl Send for LogBuffer {
}
unsafe impl Sync for LogBuffer {
}
impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { ... }
    fn flush(&mut self) -> std::io::Result<()> { ... }
}
```
## runtime/src/tests/issues.rs
```rust
use crate::*;
```
## runtime/src/tests/kernel.rs
```rust
use crate::*;
use quickcheck::*;
```
## runtime/src/tests/mod.rs
```rust
```
## runtime/src/tests/runtime.rs
```rust
use extism_manifest::{HttpRequest, MemoryOptions};
use crate::*;
use std::{collections::HashMap, io::Write, time::Instant};
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
pub struct Count { ... }
```
## runtime/src/timer.rs
```rust
use crate::*;
impl Timer {
    pub fn init(timer: &mut Option<Timer>) -> std::sync::mpsc::Sender<TimerAction> { ... }
}
impl Drop for Timer {
    fn drop(&mut self) { ... }
}
```
