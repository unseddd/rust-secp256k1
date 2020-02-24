use crate::src::src::secp256k1::{
    memcpy, memset, secp256k1_context, secp256k1_ecdsa_signature,
    secp256k1_ecdsa_signature_parse_compact, size_t,
};
use ::libc;
/* These rules specify the order of arguments in API calls:
 *
 * 1. Context pointers go first, followed by output arguments, combined
 *    output/input arguments, and finally input-only arguments.
 * 2. Array lengths always immediately the follow the argument whose length
 *    they describe, even if this violates rule 1.
 * 3. Within the OUT/OUTIN/IN groups, pointers to data that is typically generated
 *    later go first. This means: signatures, public nonces, private nonces,
 *    messages, public keys, secret keys, tweaks.
 * 4. Arguments that are not data pointers go last, from more complex to less
 *    complex: function pointers, algorithm names, messages, void pointers,
 *    counts, flags, booleans.
 * 5. Opaque data pointers follow the function pointer they are to be passed to.
 */
/* * Opaque data structure that holds context information (precomputed tables etc.).
 *
 *  The purpose of context structures is to cache large precomputed data tables
 *  that are expensive to construct, and also to maintain the randomization data
 *  for blinding.
 *
 *  Do not create a new context object for each operation, as construction is
 *  far slower than all other API calls (~100 times slower than an ECDSA
 *  verification).
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API calls that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
 *  and secp256k1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */

/* *********************************************************************
 * Copyright (c) 2015 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
/* ***
 * Please do not link this file directly. It is not part of the libsecp256k1
 * project and does not promise any stability in its API, functionality or
 * presence. Projects which use this code should instead copy this header
 * and its accompanying .c file directly into their codebase.
 ****/
/* This file defines a function that parses DER with various errors and
 * violations. This is not a part of the library itself, because the allowed
 * violations are chosen arbitrarily and do not follow or establish any
 * standard.
 *
 * In many places it matters that different implementations do not only accept
 * the same set of valid signatures, but also reject the same set of signatures.
 * The only means to accomplish that is by strictly obeying a standard, and not
 * accepting anything else.
 *
 * Nonetheless, sometimes there is a need for compatibility with systems that
 * use signatures which do not strictly obey DER. The snippet below shows how
 * certain violations are easily supported. You may need to adapt it.
 *
 * Do not use this for new systems. Use well-defined DER or compact signatures
 * instead if you have the choice (see secp256k1_ecdsa_signature_parse_der and
 * secp256k1_ecdsa_signature_parse_compact).
 *
 * The supported violations are:
 * - All numbers are parsed as nonnegative integers, even though X.609-0207
 *   section 8.3.3 specifies that integers are always encoded as two's
 *   complement.
 * - Integers can have length 0, even though section 8.3.1 says they can't.
 * - Integers with overly long padding are accepted, violation section
 *   8.3.2.
 * - 127-byte long length descriptors are accepted, even though section
 *   8.1.3.5.c says that they are not.
 * - Trailing garbage data inside or after the signature is ignored.
 * - The length descriptor of the sequence is ignored.
 *
 * Compared to for example OpenSSL, many violations are NOT supported:
 * - Using overly long tag descriptors for the sequence or integers inside,
 *   violating section 8.1.2.2.
 * - Encoding primitive integers as constructed values, violating section
 *   8.3.1.
 */
/* * Parse a signature in "lax DER" format
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args: ctx:      a secp256k1 context object
 *  Out:  sig:      a pointer to a signature object
 *  In:   input:    a pointer to the signature to be parsed
 *        inputlen: the length of the array pointed to be input
 *
 *  This function will accept any valid DER encoded signature, even if the
 *  encoded numbers are out of range. In addition, it will accept signatures
 *  which violate the DER spec in various ways. Its purpose is to allow
 *  validation of the Bitcoin blockchain, which includes non-DER signatures
 *  from before the network rules were updated to enforce DER. Note that
 *  the set of supported violations is a strict subset of what OpenSSL will
 *  accept.
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature validation with it is
 *  guaranteed to fail for every message and public key.
 */
/* *********************************************************************
 * Copyright (c) 2015 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#[no_mangle]
pub unsafe extern "C" fn ecdsa_signature_parse_der_lax(
    ctx: *const secp256k1_context,
    sig: *mut secp256k1_ecdsa_signature,
    input: *const libc::c_uchar,
    inputlen: size_t,
) -> libc::c_int {
    let mut rpos: size_t;
    let mut rlen: size_t;
    let mut spos: size_t;
    let mut slen: size_t;
    let mut pos: size_t = 0;
    let mut lenbyte: size_t;
    let mut tmpsig: [libc::c_uchar; 64] = [0; 64];
    let mut overflow: libc::c_int = 0 as libc::c_int;
    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig.as_mut_ptr());
    /* Sequence tag byte */
    if pos == inputlen || *input.add(pos) as libc::c_int != 0x30 as libc::c_int {
        return 0 as libc::c_int;
    }
    pos = pos.wrapping_add(1);
    /* Sequence length bytes */
    if pos == inputlen {
        return 0 as libc::c_int;
    }
    let fresh0 = pos;
    pos = pos.wrapping_add(1);
    lenbyte = *input.add(fresh0) as size_t;
    if lenbyte & 0x80 != 0 {
        lenbyte = lenbyte.wrapping_sub(0x80) as size_t as size_t;
        if lenbyte > inputlen.wrapping_sub(pos) {
            return 0 as libc::c_int;
        }
        pos = pos.wrapping_add(lenbyte);
    }
    /* Integer tag byte for R */
    if pos == inputlen || *input.add(pos) as libc::c_int != 0x2 as libc::c_int {
        return 0 as libc::c_int;
    }
    pos = pos.wrapping_add(1);
    /* Integer length for R */
    if pos == inputlen {
        return 0 as libc::c_int;
    }
    let fresh1 = pos;
    pos = pos.wrapping_add(1);
    lenbyte = *input.add(fresh1) as size_t;
    if lenbyte & 0x80 != 0 {
        lenbyte = lenbyte.wrapping_sub(0x80) as size_t as size_t;
        if lenbyte > inputlen.wrapping_sub(pos) {
            return 0 as libc::c_int;
        }
        while lenbyte > 0 && *input.add(pos) as size_t == 0 {
            pos = pos.wrapping_add(1);
            lenbyte = lenbyte.wrapping_sub(1)
        }
        if lenbyte >= core::mem::size_of::<size_t>() {
            return 0 as libc::c_int;
        }
        rlen = 0;
        while lenbyte > 0 {
            rlen = (rlen << 8 as libc::c_int).wrapping_add(*input.add(pos) as size_t);
            pos = pos.wrapping_add(1);
            lenbyte = lenbyte.wrapping_sub(1)
        }
    } else {
        rlen = lenbyte
    }
    if rlen > inputlen.wrapping_sub(pos) {
        return 0 as libc::c_int;
    }
    rpos = pos;
    pos = pos.wrapping_add(rlen);
    /* Integer tag byte for S */
    if pos == inputlen || *input.add(pos) as libc::c_int != 0x2 as libc::c_int {
        return 0 as libc::c_int;
    }
    pos = pos.wrapping_add(1);
    /* Integer length for S */
    if pos == inputlen {
        return 0 as libc::c_int;
    }
    let fresh2 = pos;
    pos = pos.wrapping_add(1);
    lenbyte = *input.add(fresh2) as size_t;
    if lenbyte & 0x80 != 0 {
        lenbyte = lenbyte.wrapping_sub(0x80) as size_t as size_t;
        if lenbyte > inputlen.wrapping_sub(pos) {
            return 0 as libc::c_int;
        }
        while lenbyte > 0 && *input.add(pos) as libc::c_int == 0 as libc::c_int {
            pos = pos.wrapping_add(1);
            lenbyte = lenbyte.wrapping_sub(1)
        }
        if lenbyte >= core::mem::size_of::<size_t>() {
            return 0;
        }
        slen = 0;
        while lenbyte > 0 {
            slen = (slen << 8).wrapping_add(*input.add(pos) as size_t);
            pos = pos.wrapping_add(1);
            lenbyte = lenbyte.wrapping_sub(1)
        }
    } else {
        slen = lenbyte
    }
    if slen > inputlen.wrapping_sub(pos) {
        return 0 as libc::c_int;
    }
    spos = pos;
    pos = pos.wrapping_add(slen);
    /* Ignore leading zeroes in R */
    while rlen > 0 && *input.add(rpos) as libc::c_int == 0 as libc::c_int {
        rlen = rlen.wrapping_sub(1);
        rpos = rpos.wrapping_add(1)
    }
    /* Copy R value */
    if rlen > 32 {
        overflow = 1 as libc::c_int
    } else {
        memcpy(
            tmpsig
                .as_mut_ptr()
                .offset(32 as libc::c_int as isize)
                .offset(-(rlen as isize)) as *mut libc::c_void,
            input.add(rpos) as *const libc::c_void,
            rlen,
        );
    }
    /* Ignore leading zeroes in S */
    while slen > 0 && *input.add(spos) as libc::c_int == 0 as libc::c_int {
        slen = slen.wrapping_sub(1);
        spos = spos.wrapping_add(1)
    }
    /* Copy S value */
    if slen > 32 {
        overflow = 1 as libc::c_int
    } else {
        memcpy(
            tmpsig
                .as_mut_ptr()
                .offset(64 as libc::c_int as isize)
                .offset(-(slen as isize)) as *mut libc::c_void,
            input.add(spos) as *const libc::c_void,
            slen,
        );
    }
    if overflow == 0 {
        overflow = (secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig.as_mut_ptr()) == 0)
            as libc::c_int
    }
    if overflow != 0 {
        memset(
            tmpsig.as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            64,
        );
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig.as_mut_ptr());
    }
    return 1 as libc::c_int;
}
