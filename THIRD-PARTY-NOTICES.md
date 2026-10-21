# Third-party notices — archive-mirror development source

Archive-mirror original Zog source, tests, metadata and deployment examples are
licensed at the user's choice under **BSD-3-Clause OR GPL-3.0-only**, as specified
by LICENSE and the complete LICENSES/ texts. This first-party grant does not
change the terms of independent dependencies or upstream archive payloads.

Runtime dependencies are installed separately and retain their own licenses:
- Django 5.2.x (BSD-3-Clause), https://www.djangoproject.com/
- Waitress 3.x (ZPL-2.1), https://github.com/Pylons/waitress
- cryptography (Apache-2.0 OR BSD-3-Clause), https://github.com/pyca/cryptography
- PyJWT 2.10.x (MIT), https://github.com/jpadilla/pyjwt
- Zog host-identify (separately published Zog grant), https://github.com/zog144/host-identify

These listings are dependency declarations, not evidence that dependency wheels,
native/compiled transitive components or source archives are bundled in this
repository. Verify exact installed versions, licenses and required notices at
the actual distribution and installation boundary.

At runtime archive-mirror may acquire and serve separately licensed upstream
Git exports and root filesystem archives. Those payloads live outside the source
Git tree and require their own authorization and provenance checks. No precompiled
rootfs or archive download release is approved by publication of this source.
Private historical verification reports, access credentials and old license
declarations were intentionally excluded from the clean-history export.
