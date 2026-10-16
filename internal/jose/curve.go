package jose

import "crypto/elliptic"

func ecdsaCurve() elliptic.Curve { return elliptic.P256() }
