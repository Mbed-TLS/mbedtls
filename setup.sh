#!/bin/bash

echo "Some useful env info"
printenv
echo ${NEXUS_PWD} | sha256sum

echo "Installing the necessary packages"
apt-get -qq update && apt-get -qq install -y openjdk-8-jdk unzip wget curl git python python3
mkdir -p ~/.ssh/
mkdir -p /opt/

echo "Downloading and installing the Android SDK"
DL_TARGET_SDK=/opt/android-sdk.zip
curl -sSf --user "vhtest:$NEXUS_PWD" -o $DL_TARGET_SDK https://nexus.mersive.xyz/repository/vhserver/sdk-tools-linux-4333796.zip
mkdir -p $ANDROID_HOME
unzip -q -d $ANDROID_HOME $DL_TARGET_SDK

echo "Configuring the SDK"
mkdir -p /root/.android
touch /root/.android/repositories.cfg
yes | sdkmanager --licenses > /dev/null
sdkmanager "tools" "platform-tools" "build-tools;25.0.3" "platforms;android-25" "add-ons;addon-google_apis-google-24" > /dev/null
sdkmanager "extras;android;m2repository" "extras;google;google_play_services" "patcher;v4" > /dev/null
sdkmanager "cmake;3.6.4111459" > /dev/null

echo "Downloading and installing the Android NDK"
DL_TARGET_NDK=/opt/android-ndk-r20b-linux-x86_64.zip
wget -q -O $DL_TARGET_NDK https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip
unzip -q -d $ANDROID_NDK_HOME $DL_TARGET_NDK
