When a PR is created against this repo's `all_components.yml` file to bump a
component's `latest_release`, final integration testing will commence to
validate the component before release. Upon success, a release will trigger,
the PR will merge, and a subsequent PR will be created against the repo for
each component listed in `required_by`. Each component has its own local
`required_components.yml` file which tracks dependent component versions, and
this PR proposal will bump the recently released component's version in
`required_components.yml`. It is assumed that the deployment / installation of
a component will use `required_components.yml` to determine which component
dependencies and versions are to be installed.
