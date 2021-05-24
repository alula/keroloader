#!/bin/bash

cd unicorn
export UNICORN_ARCHS="x86" 
export NDK=~/opt/android-sdk/ndk/21.4.7075529 

./make.sh cross-android_arm64
#UNICORN_ARCHS=x86 NDK=~/opt/android-sdk/ndk/21.4.7075529 ./make.sh cross-android_arm

cd ..
mkdir -p prebuilts/android/arm64-v8a
cp -f ./unicorn/libunicorn.a prebuilts/android/arm64-v8a/libunicorn.a