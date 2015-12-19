# Contributing
Feedback, and contributions from our community create better code for everyone.
Whether it's a new feature, correction, or additional documentation,
we welcome pull requests.

This document contains guidelines for contributing code and filing issues.

## Contributing Code
* Code should follow the [PEP08](https://www.python.org/dev/peps/pep-0008/)
  style standard.
  If existing code does not match the PEP08 format, it is strongly recommended
  that a single commit be used to update the code to PEP08 format before the
  bug/feature fixes are put in.
* Code should be unit tested using
  [unittest](https://docs.python.org/library/unittest.html) in the tests
  folder. Preferably unit tests should be written before a bug fixes/features are
  written.
* Code must work on Python 3 interpreters. We have decided not to target the
  Python 2 interpreters at this stage.
* Code is focused on the Linux platform, but where possible, should be able to
  run on Windows.
* Before implementing a new significant feature, please review the
  [ROADMAP](ROADMAP.md) to ensure that effort is not duplicated, or waiting on previous steps

## Reporting An Issue, or Requesting a New Feature
* Check to see if there's an existing
  [issue](https://github.com/neilramsay/dnssec-zonetools/issues), or
  [pull request](https://github.com/neilramsay/dnssec-zonetools/pulls) for the bug/feature.
* If there isn't an existing issue there, please file an issue. The
  ideal report includes:
  * A description of the problem/suggestion,
  * A code sample that demonstrates the issue,
  * Including the versions of your:
    * python interpreter
    * OS
    * optionally any other python dependencies involved
