Contents
========
This directory contains tools for developers working on this repository.

check-doc.py
============

Check if all command line args are documented. The return value indicates the
number of undocumented args.

gen-manpages.sh
===============

A small script to automatically create manpages in ../../doc/man by running the release binaries with the -help option.
This requires help2man which can be found at: https://www.gnu.org/software/help2man/

With in-tree builds this tool can be run from any directory within the
repostitory. To use this tool with out-of-tree builds set `BUILDDIR`. For
example:

```bash
BUILDDIR=$PWD/build contrib/devtools/gen-manpages.sh
```

github-merge.py
===============

A small script to automate merging pull-requests securely and sign them with GPG.

For example:

  ./github-merge.py 3077

(in any git repository) will help you merge pull request #3077 for the
ioncoincore/ion repository.

What it does:
* Fetch master and the pull request.
* Locally construct a merge commit.
* Show the diff that merge results in.
* Ask you to verify the resulting source tree (so you can do a make
check or whatever).
* Ask you whether to GPG sign the merge commit.
* Ask you whether to push the result upstream.

This means that there are no potential race conditions (where a
pullreq gets updated while you're reviewing it, but before you click
merge), and when using GPG signatures, that even a compromised GitHub
couldn't mess with the sources.

Setup
---------
Configuring the github-merge tool for the Ion repository is done in the following way:

    git config githubmerge.repository ioncoincore/ion
    git config githubmerge.testcmd "make -j4 check" (adapt to whatever you want to use for testing)
    git config --global user.signingkey mykeyid (if you want to GPG sign)

optimize-pngs.py
================

A script to optimize png files in the ION
repository (requires pngcrush).

fix-copyright-headers.py
===========================

Every year newly updated files need to have its copyright headers updated to reflect the current year.
If you run this script from src/ it will automatically update the year on the copyright header for all
.cpp and .h files if these have a git commit from the current year.

For example a file changed in 2014 (with 2014 being the current year):
```// Copyright (c) 2009-2013 The Bitcoin developers```

would be changed to:
```// Copyright (c) 2009-2014 The Bitcoin developers```

logprint-scanner.py
===================
LogPrint and LogPrintf are known to throw exceptions when the number of arguments supplied to the
LogPrint(f) function is not the same as the number of format specifiers.

Ideally, the presentation of this mismatch would be at compile-time, but instead it is at run-time.

This script scans the src/ directory recursively and looks in each .cpp/.h file and identifies all
errorneous LogPrint(f) calls where the number of arguments do not match.

The filename and line number of the errorneous occurence is given.

The script returns with the number of erroneous occurences as an error code to help facilitate
integration with a continuous integration system.

The script can be ran from any working directory inside the git repository.

symbol-check.py
===============

A script to check that the (Linux) executables produced by gitian only contain
allowed gcc, glibc and libstdc++ version symbols. This makes sure they are
still compatible with the minimum supported Linux distribution versions.

Example usage after a gitian build:

    find ../gitian-builder/build -type f -executable | xargs python contrib/devtools/symbol-check.py

If only supported symbols are used the return value will be 0 and the output will be empty.

If there are 'unsupported' symbols, the return value will be 1 a list like this will be printed:

    .../64/test_ion: symbol memcpy from unsupported version GLIBC_2.14
    .../64/test_ion: symbol __fdelt_chk from unsupported version GLIBC_2.15
    .../64/test_ion: symbol std::out_of_range::~out_of_range() from unsupported version GLIBCXX_3.4.15
    .../64/test_ion: symbol _ZNSt8__detail15_List_nod from unsupported version GLIBCXX_3.4.15

update-translations.py
======================

Run this script from the root of the repository to update all translations from transifex.
It will do the following automatically:

- fetch all translations
- post-process them into valid and committable format
- add missing translations to the build system (TODO)

See doc/translation-process.md for more information.

png2icns
========

Run this script in a folder where your PNG's which you require for icns are.

_Importan Info_: _**Only** convert the **icons that match sizes icns supports**: (16x16, 32x32, 128x128, 256x256, 512x512 and 1024x1024 pixels)_


```
png2icns ion.icns ion_16x16x32.png ion_128x128x32.png ion_256x256x32.png ion_48x48x32.png ion_512x512x32.png
Using icns type 'is32', mask 's8mk' for 'ion_16x16x32.png'
Using icns type 'it32', mask 't8mk' for 'ion_128x128x32.png'
Using icns type 'ic08' (ARGB) for 'ion_256x256x32.png'
Using icns type 'ih32', mask 'h8mk' for 'ion_48x48x32.png'
Using icns type 'ic09' (ARGB) for 'ion_512x512x32.png'
Saved icns file to ion.icns
```

icns2png
========

Run this script in a folder where you temporarly placed your icns file. It will extract all files.


```
icns2png -x ion.icns
----------------------------------------------------
Reading icns family from ion.icns...
 Extracting icons from ion.icns...
  Saved 'is32' element to ion_16x16x32.png.
  Saved 'il32' element to ion_32x32x32.png.
  Saved 'ih32' element to ion_48x48x32.png.
  Saved 'it32' element to ion_128x128x32.png.
  Saved 'ic08' element to ion_256x256x32.png.
  Saved 'ic09' element to ion_512x512x32.png.
Extracted 6 images from ion.icns.
```

