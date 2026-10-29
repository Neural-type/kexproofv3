#ifndef KPDOVIRPUVariants_h
#define KPDOVIRPUVariants_h

typedef struct {
    const char *identifier;
    const char *resource;
    const char *sha256;
    uint32_t blockID;
    uint32_t capacity;
    uint32_t over;
} KPDOVIRPUVariant;

static const KPDOVIRPUVariant KPDOVIRPUVariants[] = {
    {"rpu-baseline", "rpu-baseline", "406ffd6e142e9dad2dcd527880bf48ee2cfdc805832834f18761a671239d10cd", 0, 0, 0},
    {"rpu-a10-o1", "rpu-a10-o1", "f9733083429021b5a528f1bf761195019daea9724bb75bf6da1c1064efac256c", 10, 4, 1},
    {"rpu-a10-o2", "rpu-a10-o2", "5f96f0465eee04ce7136bdffc251cbf85f3d529df8cfa9d0ea5ab4062b6255e2", 10, 4, 2},
    {"rpu-a10-o3", "rpu-a10-o3", "a59df3906156b7cd5c5003cb99a31db1f1c5da4d628bc956dbc5c891b1ce2e40", 10, 4, 3},
    {"rpu-a10-o4", "rpu-a10-o4", "f0f1eb82de895f687c43e814f8da4502ac788b3c49a7122b6b426327b565e33a", 10, 4, 4},
    {"rpu-a10-o5", "rpu-a10-o5", "aff41dfc23d6f7e036868cfb0ef7f4077f93c49eb184070772781da8dbdfe9ad", 10, 4, 5},
    {"rpu-a10-o6", "rpu-a10-o6", "ae93857cbefd0154f2486611d88d997d79ab5de88b1b12d4391e6871722dc85e", 10, 4, 6},
    {"rpu-a10-o7", "rpu-a10-o7", "4ee0724a21b190d36e29234f63b1d5ad88bdb96e02fb5c90d3c1b0a98fb956eb", 10, 4, 7},
    {"rpu-a10-o8", "rpu-a10-o8", "6bead6c73a95626c6f98f5851f0423b2709cc1e30b0e750334dac3389ee07c9f", 10, 4, 8},
    {"rpu-b2-o1", "rpu-b2-o1", "956802f170a98c7c7052f082030f7fed5428776997b5aea2a9a878c01ef5c6fe", 2, 8, 1},
    {"rpu-b2-o2", "rpu-b2-o2", "1180fdcfc8543256ee9b8dd0d6ccd0e4dea2ecaa11092dee13cc605fa5c84f79", 2, 8, 2},
    {"rpu-b2-o3", "rpu-b2-o3", "318556a78c13f0155d6d399bb45d713048870bba13fd9dc8631718e238569dbb", 2, 8, 3},
    {"rpu-b2-o4", "rpu-b2-o4", "a06916602e8d8975864c90b1c8ac268fd2de012a8eed3b32ae59c933a50a902f", 2, 8, 4},
    {"rpu-b2-o5", "rpu-b2-o5", "084abed2514288fc66c619e618e1e438eb44e08d574fe47a146bf96a8ade9291", 2, 8, 5},
    {"rpu-b2-o6", "rpu-b2-o6", "d372d28c04dac9ea828cc465e072e44d23cf4caf523a8dd62f9066bc24c1f098", 2, 8, 6},
    {"rpu-b2-o7", "rpu-b2-o7", "4e44af57cf17dbacdda493eb995ea62b45a82452d07ba44643e959b2556f10ed", 2, 8, 7},
    {"rpu-b2-o8", "rpu-b2-o8", "f0c234465b8f660f45047ccaf51af5f89e80794c8ce2bd617de7942516261ad9", 2, 8, 8},
    {"rpu-c6-o1", "rpu-c6-o1", "2309d6e36ca1601e67b28ca01940f7adaa389758e275c965ff3a2a6845e0f01c", 6, 5, 1},
    {"rpu-c6-o2", "rpu-c6-o2", "12d50061d681670a591d63b639e8aacd0479dc2066d818fbcfcdaa31a0c64ee6", 6, 5, 2},
    {"rpu-c6-o3", "rpu-c6-o3", "390275a4f4620e2be943fe2c8ed79ac2f1a4f61d7e1dbcc99267ec7159c3a074", 6, 5, 3},
    {"rpu-c6-o4", "rpu-c6-o4", "209ff8b95b2fa106dc17b01a9f633f8acbe664a9db0f26e97a0f7baad9e66201", 6, 5, 4},
    {"rpu-c6-o5", "rpu-c6-o5", "ff08d7801eb80af4db04fad3bd03dce8c7e1c9f6f4da0e7f7eb74e8fca23b26e", 6, 5, 5},
    {"rpu-c6-o6", "rpu-c6-o6", "5952978527a44fccaa0fa874e210a2314df63fc8956766c5d4938b8129e546a2", 6, 5, 6},
    {"rpu-c6-o7", "rpu-c6-o7", "cff965edea9dcf3384cc5ac31bd0cfb3ba972059b4e6d731e0d0b3ece2580fd1", 6, 5, 7},
    {"rpu-c6-o8", "rpu-c6-o8", "68d230fe05b3e798a346b08742fbf28b6b86d22f3242b5220cbca3454fe9d394", 6, 5, 8},
};

static const NSUInteger KPDOVIRPUVariantCount = sizeof(KPDOVIRPUVariants) / sizeof(KPDOVIRPUVariants[0]);

#endif
