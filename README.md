<p align="center">
  <img src="cicd-sensor.png" alt="cicd-sensor logo" width="160">
</p>

# cicd-sensor

🚧 Currently under development. Not yet ready for use.

## Quick Start

Add the cicd-sensor action to your GitHub Actions workflow:

```yaml
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: cicd-sensor/cicd-sensor-action@v0.0.2
      - uses: actions/checkout@v6

      - name: Build
        run: make test
```
