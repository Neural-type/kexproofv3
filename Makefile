ARCHS = arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = KexProofV3

KexProofV3_FILES = $(wildcard Sources/*.m)
KexProofV3_FRAMEWORKS = UIKit Foundation CoreFoundation QuartzCore
KexProofV3_PRIVATE_FRAMEWORKS = IOKit
KexProofV3_CFLAGS = -fobjc-arc -O2 -Wall -Wextra -Wno-error -Wno-deprecated-declarations -ISources
KexProofV3_INSTALL_PATH = /Applications
KexProofV3_RESOURCE_DIRS = Resources
KexProofV3_CODESIGN_FLAGS = -SResources/entitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
