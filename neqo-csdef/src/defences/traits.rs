use crate::trace::Trace;

/// Trait for defence implementations to be used with FlowShaper
pub trait Defence {
    /// Return a trace to be shaped or padded towards.
    fn trace(&self) -> Trace;
    /// True if the defence is a padding only defence, false otherweise.
    fn is_padding_only(&self) -> bool;
}
