package sbom

import (
    "bytes"
    "fmt"
    "github.com/anchore/syft/internal/formats/cyclonedxjson"
    "github.com/anchore/syft/syft/artifact"
    "github.com/anchore/syft/syft/pkg"
    "github.com/anchore/syft/syft/pkg/cataloger/common"
    "io"
)

// NewSBOMCataloger returns a new SBOM cataloger object loaded from saved SBOM JSON.
func NewSBOMCataloger() *common.GenericCataloger {
    globParsers := map[string]common.ParserFn{
        "**/deps.json":         parseSBOM,
        "**/sbom.json":         parseSBOM,
    }

    return common.NewGenericCataloger(nil, globParsers, "sbom-cataloger")
}

func parseSBOM(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
    by, err := io.ReadAll(reader)
    if err != nil {
        return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
    }

    f := cyclonedxjson.Format()

    s, err := f.Decode(bytes.NewReader(by))
    if err != nil {
        return nil, nil, fmt.Errorf("unable to decode sbom: %w", err)
    }

    var packages []*pkg.Package
    for _, p := range s.Artifacts.PackageCatalog.Sorted() {
        x := p //copy
        packages = append(packages, &x)
    }

    return packages, nil, nil
}
