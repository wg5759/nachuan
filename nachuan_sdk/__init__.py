"""Public, versioned SDK surface for Nachuan isolated plugins and bridges."""

SDK_API_VERSION = "1"
__version__ = "1.0.0"

from nachuan_sdk.bridges import (
    BridgeComponentV1,
    EcosystemBridgePlanV1,
    UpstreamSourcePinV1,
    build_deepseek_harness_bridge_plan,
    build_openclaw_bridge_plan,
)
from nachuan_sdk.bundle import (
    BundleBuildReceiptV1,
    IsolatedTransformPluginSpecV1,
    build_signed_transform_bundle,
    default_isolated_limits,
)

__all__ = [
    "BridgeComponentV1",
    "BundleBuildReceiptV1",
    "EcosystemBridgePlanV1",
    "IsolatedTransformPluginSpecV1",
    "UpstreamSourcePinV1",
    "SDK_API_VERSION",
    "__version__",
    "build_deepseek_harness_bridge_plan",
    "build_openclaw_bridge_plan",
    "build_signed_transform_bundle",
    "default_isolated_limits",
]
