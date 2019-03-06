// MIT License

// Copyright (c) 2019 Matthew Knight

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Copied directly from https://github.com/retep998/winapi-rs

#![cfg(all(windows, target_arch = "x86"))]
extern crate winapi;
use std::mem::{size_of, align_of};
#[cfg(feature = "bcrypt")] #[test]
fn shared_bcrypt() {
    use winapi::shared::bcrypt::*;
    assert_eq!(size_of::<BCRYPT_KEY_LENGTHS_STRUCT>(), 12);
    assert_eq!(align_of::<BCRYPT_KEY_LENGTHS_STRUCT>(), 4);
    assert_eq!(size_of::<BCRYPT_OID>(), 8);
    assert_eq!(align_of::<BCRYPT_OID>(), 4);
    assert_eq!(size_of::<BCRYPT_OID_LIST>(), 8);
    assert_eq!(align_of::<BCRYPT_OID_LIST>(), 4);
    assert_eq!(size_of::<BCRYPT_PKCS1_PADDING_INFO>(), 4);
    assert_eq!(align_of::<BCRYPT_PKCS1_PADDING_INFO>(), 4);
    assert_eq!(size_of::<BCRYPT_PSS_PADDING_INFO>(), 8);
    assert_eq!(align_of::<BCRYPT_PSS_PADDING_INFO>(), 4);
    assert_eq!(size_of::<BCRYPT_OAEP_PADDING_INFO>(), 12);
    assert_eq!(align_of::<BCRYPT_OAEP_PADDING_INFO>(), 4);
    assert_eq!(size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>(), 64);
    assert_eq!(align_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>(), 8);
    assert_eq!(size_of::<BCryptBuffer>(), 12);
    assert_eq!(align_of::<BCryptBuffer>(), 4);
    assert_eq!(size_of::<BCryptBufferDesc>(), 12);
    assert_eq!(align_of::<BCryptBufferDesc>(), 4);
    assert_eq!(size_of::<BCRYPT_KEY_BLOB>(), 4);
    assert_eq!(align_of::<BCRYPT_KEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_RSAKEY_BLOB>(), 24);
    assert_eq!(align_of::<BCRYPT_RSAKEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_ECCKEY_BLOB>(), 8);
    assert_eq!(align_of::<BCRYPT_ECCKEY_BLOB>(), 4);
    assert_eq!(size_of::<SSL_ECCKEY_BLOB>(), 8);
    assert_eq!(align_of::<SSL_ECCKEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_ECCFULLKEY_BLOB>(), 32);
    assert_eq!(align_of::<BCRYPT_ECCFULLKEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_DH_KEY_BLOB>(), 8);
    assert_eq!(align_of::<BCRYPT_DH_KEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_DH_PARAMETER_HEADER>(), 12);
    assert_eq!(align_of::<BCRYPT_DH_PARAMETER_HEADER>(), 4);
    assert_eq!(size_of::<BCRYPT_DSA_KEY_BLOB>(), 52);
    assert_eq!(align_of::<BCRYPT_DSA_KEY_BLOB>(), 4);
    assert_eq!(size_of::<BCRYPT_DSA_KEY_BLOB_V2>(), 28);
    assert_eq!(align_of::<BCRYPT_DSA_KEY_BLOB_V2>(), 4);
    assert_eq!(size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>(), 12);
    assert_eq!(align_of::<BCRYPT_KEY_DATA_BLOB_HEADER>(), 4);
    assert_eq!(size_of::<BCRYPT_DSA_PARAMETER_HEADER>(), 56);
    assert_eq!(align_of::<BCRYPT_DSA_PARAMETER_HEADER>(), 4);
    assert_eq!(size_of::<BCRYPT_DSA_PARAMETER_HEADER_V2>(), 32);
    assert_eq!(align_of::<BCRYPT_DSA_PARAMETER_HEADER_V2>(), 4);
    assert_eq!(size_of::<BCRYPT_ECC_CURVE_NAMES>(), 8);
    assert_eq!(align_of::<BCRYPT_ECC_CURVE_NAMES>(), 4);
    assert_eq!(size_of::<BCRYPT_MULTI_HASH_OPERATION>(), 16);
    assert_eq!(align_of::<BCRYPT_MULTI_HASH_OPERATION>(), 4);
    assert_eq!(size_of::<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT>(), 8);
    assert_eq!(align_of::<BCRYPT_MULTI_OBJECT_LENGTH_STRUCT>(), 4);
    assert_eq!(size_of::<BCRYPT_ALGORITHM_IDENTIFIER>(), 12);
    assert_eq!(align_of::<BCRYPT_ALGORITHM_IDENTIFIER>(), 4);
    assert_eq!(size_of::<BCRYPT_PROVIDER_NAME>(), 4);
    assert_eq!(align_of::<BCRYPT_PROVIDER_NAME>(), 4);
    assert_eq!(size_of::<BCRYPT_INTERFACE_VERSION>(), 4);
    assert_eq!(align_of::<BCRYPT_INTERFACE_VERSION>(), 2);
    assert_eq!(size_of::<CRYPT_INTERFACE_REG>(), 16);
    assert_eq!(align_of::<CRYPT_INTERFACE_REG>(), 4);
    assert_eq!(size_of::<CRYPT_IMAGE_REG>(), 12);
    assert_eq!(align_of::<CRYPT_IMAGE_REG>(), 4);
    assert_eq!(size_of::<CRYPT_PROVIDER_REG>(), 16);
    assert_eq!(align_of::<CRYPT_PROVIDER_REG>(), 4);
    assert_eq!(size_of::<CRYPT_PROVIDERS>(), 8);
    assert_eq!(align_of::<CRYPT_PROVIDERS>(), 4);
    assert_eq!(size_of::<CRYPT_CONTEXT_CONFIG>(), 8);
    assert_eq!(align_of::<CRYPT_CONTEXT_CONFIG>(), 4);
    assert_eq!(size_of::<CRYPT_CONTEXT_FUNCTION_CONFIG>(), 8);
    assert_eq!(align_of::<CRYPT_CONTEXT_FUNCTION_CONFIG>(), 4);
    assert_eq!(size_of::<CRYPT_CONTEXTS>(), 8);
    assert_eq!(align_of::<CRYPT_CONTEXTS>(), 4);
    assert_eq!(size_of::<CRYPT_CONTEXT_FUNCTIONS>(), 8);
    assert_eq!(align_of::<CRYPT_CONTEXT_FUNCTIONS>(), 4);
    assert_eq!(size_of::<CRYPT_CONTEXT_FUNCTION_PROVIDERS>(), 8);
    assert_eq!(align_of::<CRYPT_CONTEXT_FUNCTION_PROVIDERS>(), 4);
    assert_eq!(size_of::<CRYPT_PROPERTY_REF>(), 12);
    assert_eq!(align_of::<CRYPT_PROPERTY_REF>(), 4);
    assert_eq!(size_of::<CRYPT_IMAGE_REF>(), 8);
    assert_eq!(align_of::<CRYPT_IMAGE_REF>(), 4);
    assert_eq!(size_of::<CRYPT_PROVIDER_REF>(), 28);
    assert_eq!(align_of::<CRYPT_PROVIDER_REF>(), 4);
    assert_eq!(size_of::<CRYPT_PROVIDER_REFS>(), 8);
    assert_eq!(align_of::<CRYPT_PROVIDER_REFS>(), 4);
}
