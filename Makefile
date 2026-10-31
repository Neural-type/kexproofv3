ARCHS = arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = KexProofV3

KexProofV3_FILES = $(wildcard Sources/*.m)
KexProofV3_FRAMEWORKS = UIKit Foundation CoreFoundation QuartzCore Security IOSurface CoreGraphics ImageIO CoreMedia VideoToolbox AVFoundation AudioToolbox
KexProofV3_PRIVATE_FRAMEWORKS = IOKit
KexProofV3_LDFLAGS = -lz
KexProofV3_CFLAGS = -fobjc-arc -O2 -Wall -Wextra -Wno-error -Wno-deprecated-declarations -ISources -DKP_IOSURFACE27_ENABLE_RACE=1 -DKP_IOAUDIO27_ENABLE_ARMED=1 -DKP_M2SCALER27_ENABLE_ARMED=1 -DKP_AGXSPILL27_ENABLE_ARMED=1 -DKP_IOKIT_FUZZER_ENABLE_ARMED=1 -DKP_GLYPH27_ENABLE_ARMED=1 -DKP_CGTYPE527_ENABLE_ARMED=1 -DKP_CGTYPE5STACK_ENABLE_ARMED=1 -DKP_DOVIRPU_ENABLE_ARMED=1 -DKP_HEIC112621_ENABLE_ARMED=1 -DKP_AVE112705_ENABLE_ARMED=1 -DKP_CMCA27_ENABLE_ARMED=1
KexProofV3_INSTALL_PATH = /Applications
KexProofV3_RESOURCE_DIRS = Resources
KexProofV3_CODESIGN_FLAGS = -SResources/entitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
