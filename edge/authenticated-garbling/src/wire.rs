//! Various wirelabel representations used in authenticated garbling.

use crate::{PartyEvaluator, PartyGarbler};
use fancy_garbling::WireMod2;
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_field_binary::F2;

/// A [`fancy_traits::Fancy`] wire for the garbler's offline phase.
#[derive(Clone, Copy, Default)]
pub struct OfflineWire {
    wirelabel: WireMod2,
    auth_share: AuthShare<PartyGarbler>,
}

impl OfflineWire {
    pub(crate) fn new(wirelabel: WireMod2, auth_share: AuthShare<PartyGarbler>) -> Self {
        Self {
            wirelabel,
            auth_share,
        }
    }

    pub(crate) fn wirelabel(&self) -> WireMod2 {
        self.wirelabel
    }

    pub(crate) fn auth_share(&self) -> AuthShare<PartyGarbler> {
        self.auth_share
    }
}

impl core::fmt::Debug for OfflineWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wire")
            .field("wirelabel", &self.wirelabel)
            .field("auth_share", &())
            .finish()
    }
}

/// A [`fancy_traits::Fancy`] wire for the garbler's validation phase.
#[derive(Clone, Copy, Default)]
pub struct ValidatorWire {
    masked_value: F2,
    auth_share: AuthShare<PartyGarbler>,
}

impl ValidatorWire {
    pub(crate) fn new(masked_value: F2, auth_share: AuthShare<PartyGarbler>) -> Self {
        Self {
            masked_value,
            auth_share,
        }
    }

    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }

    pub(crate) fn auth_share(&self) -> AuthShare<PartyGarbler> {
        self.auth_share
    }
}

impl core::fmt::Debug for ValidatorWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorWire")
            .field("masked_value", &self.masked_value)
            .field("auth_share", &())
            .finish()
    }
}

/// A [`fancy_traits::Fancy`] wire for the evaluator.
///
/// An authenticated garbling wirelabel is a wirelabel $`L`$ alongside (1) an
/// [`AuthShare`] $`\lambda`$ of $`L`$s color bit, and (2)  the masked value $`w
/// \oplus \lambda`$, where $`w`$ is the actual bit represented by the
/// wirelabel.
#[derive(Clone, Copy, Default)]
pub struct EvaluatorWire {
    /// A masked value $`w \oplus \lambda`$.
    masked_value: F2,
    /// An optional  wirelabel $`L`$.
    wire_label: WireMod2,
    /// Sharing of the color bit $`\lambda`$.
    auth_share: AuthShare<PartyEvaluator>,
}

impl EvaluatorWire {
    /// Create a new `AuthenticatedWireMod2` given a masked value, the underlying wirelabel
    /// $`L`$, and its associated color bit share $`\langle \lambda \rangle`$.
    pub(crate) fn new(
        masked_value: F2,
        wire_label: WireMod2,
        auth_share: AuthShare<PartyEvaluator>,
    ) -> Self {
        EvaluatorWire {
            masked_value,
            wire_label,
            auth_share,
        }
    }

    /// The masked value associated with this wire.
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }

    /// The wirelabel $`L`$ associated with this wire.
    pub(crate) fn wire_label(&self) -> WireMod2 {
        self.wire_label
    }

    /// The authenticated share $`\langle \lambda \rangle`$ associated with this
    /// wire.
    pub(crate) fn auth_share(&self) -> AuthShare<PartyEvaluator> {
        self.auth_share
    }
}

impl core::fmt::Debug for EvaluatorWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedWireMod2")
            .field("masked_value", &self.masked_value)
            .field("wire_label", &self.wire_label)
            .field("auth_share", &())
            .finish()
    }
}
