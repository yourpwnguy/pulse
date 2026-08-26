//! Shared state for the live animation.
//!
//! The pipeline writes to shared state, the animation thread reads from it.
//! This module contains the shared state and the mutex helper.

use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Mutex;
use std::time::Instant;

use super::Stage;

/// Shared state: the worker thread reads it, the pipeline writes it.
pub(crate) struct Shared {
    /// When the current stage began, for the minimum-dwell pacing.
    pub started: Mutex<Instant>,
    /// Completed stages with their one-line summary.
    pub done: Mutex<Vec<(Stage, String)>>,
    /// The stage currently running, if any.
    pub current: Mutex<Option<Stage>>,
    /// Recent detail lines for the running stage.
    pub detail: Mutex<Vec<String>>,
    pub done_count: AtomicUsize,
    pub total: AtomicUsize,
    pub running: AtomicBool,
}

/// Poison recovery: a panicked writer must not take the animation down with it.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
