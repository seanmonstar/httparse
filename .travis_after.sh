#!/bin/bash
set -ev
if [[ $TRAVIS_RUST_VERSION = stable ]]; then
  wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
  tar xzf master.tar.gz
  mkdir kcov-master/build
  cd kcov-master/build
  cmake ..
  make
  make install DESTDIR=../tmp
  cd ../..
  ls target/debug
  ./kcov-master/tmp/usr/local/bin/kcov --coveralls-id=$TRAVIS_JOB_ID --exclude-pattern=/.cargo target/kcov target/debug/httparse-*
  if [[ $TRAVIS_BRANCH = master && $TRAVIS_PULL_REQUEST = false ]]; then
    cargo doc --no-deps
    echo "<meta http-equiv=refresh content=0;url=httparse/index.html>" > target/doc/index.html
    pip install --user ghp-import &&
    /home/travis/.local/bin/ghp-import -n target/doc &&
    git push -fq https://${TOKEN}@github.com/${TRAVIS_REPO_SLUG}.git gh-pages
  fi
fi


