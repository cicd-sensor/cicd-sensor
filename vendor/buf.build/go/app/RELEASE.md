# Releasing

This document outlines how to create a release of app-go.

1. Clone the repo, ensuring you have the latest main.

2. Review all commits in the new release and for each PR check an appropriate label is used and edit
   the title to be meaningful to end users.

3. Using the Github UI, create a new release.

   - Under “Choose a tag”, type in “vX.Y.Z” to create a new tag for the release upon publish.
   - Target the main branch.
   - Title the Release “vX.Y.Z”.
   - Click “set as latest release”.
   - Set the last version as the “Previous tag”.
   - Edit the release notes.

4. Publish the release.
