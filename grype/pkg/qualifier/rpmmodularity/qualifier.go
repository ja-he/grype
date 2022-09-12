package rpmmodularity

import (
	"github.com/anchore/grype/grype/pkg"
)

type rpmModularity struct {
	label string
}

func (r rpmModularity) Satisfied(p pkg.Package) (bool, error) {
	if p.MetadataType == pkg.RpmdbMetadataType {
		m, ok := p.Metadata.(pkg.RpmdbMetadata)

		if !ok {
			return false, nil
		}

		if m.Modularity == r.label {
			return true, nil
		}
	}

	return false, nil
}
