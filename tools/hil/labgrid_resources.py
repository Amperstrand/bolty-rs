"""Client-side labgrid resource classes for rig resources exported through
the plain ResourceEntry fallback (#78): the exporter->coordinator wire only
carries flat scalar params, so these classes exist purely on the client and
carry no device logic — presence detection stays with HIL preflight (pcscd).
Imported by labgrid-env.yaml (`imports:`)."""

import attr

from labgrid import target_factory
from labgrid.resource.common import Resource


@target_factory.reg_resource
@attr.s(eq=False)
class NetworkSmartcardReader(Resource):
    """The ACR1252 bench reader as a coordinator-visible acquisition token."""

    vendor_id = attr.ib(default="", validator=attr.validators.instance_of(str))
    model_id = attr.ib(default="", validator=attr.validators.instance_of(str))
    id_path = attr.ib(default="", validator=attr.validators.instance_of(str))
