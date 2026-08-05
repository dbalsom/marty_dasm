// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Daniel Balsom

#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod compression;
mod disassembly;
mod template;

#[cfg(target_arch = "wasm32")]
mod bylines;
#[cfg(target_arch = "wasm32")]
mod local_storage;
#[cfg(target_arch = "wasm32")]
mod panic_report;
#[cfg(target_arch = "wasm32")]
mod query;
#[cfg(target_arch = "wasm32")]
mod web;
