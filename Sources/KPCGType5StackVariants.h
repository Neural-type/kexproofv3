#ifndef KPCGType5StackVariants_h
#define KPCGType5StackVariants_h

typedef struct {
    const char *identifier;
    const char *resource;
    const char *sha256;
    uint32_t rangeDimension;
    uint32_t colorSpaceComponents;
    uint32_t verticesPerRow;
    uint32_t rows;
    uint32_t triangles;
    uint32_t allocationSize;
} KPCGType5StackVariant;

static const KPCGType5StackVariant KPCGType5StackVariants[] = {
    {"type5-stack-r004", "cgtype5-stack-r004", "9c917ac1aa56a33df31b21ac67d8cfdbc35f241860c3f8512efbd4d860e02fbc", 4, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r008", "cgtype5-stack-r008", "4d1338ec5aa5ce67d2402ac659b32be3ffe09ae8343fb47e29f0c4a9eb55ac7f", 8, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r012", "cgtype5-stack-r012", "effe34e0e54339d2117664fad20c95bec954d6f0665e426715648e1c504c54f8", 12, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r016", "cgtype5-stack-r016", "c84507d007278fd27503cc552ab922bd04b75699c94efc07dcb6e04420f664c3", 16, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r020", "cgtype5-stack-r020", "c366d5af2ab63702edd68d4afab5dd87be76a47b9656ff6d692adb68dfc0dda1", 20, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r024", "cgtype5-stack-r024", "3eb27e088b69c3df5ee0b1dd91444e0d9d5adce4500c93a099224db7b85afa77", 24, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r028", "cgtype5-stack-r028", "63797b760ec981f0efe4b00428853bb83028ce2d2ce01b30f47881a551f2bc7a", 28, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r032", "cgtype5-stack-r032", "b8b83a1f9790d7c0eb668d5695fcdfba9ba89141ef92b6457f2977198071022d", 32, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r036", "cgtype5-stack-r036", "4ad7b81e29478286f75675455995b62de98b6b8131690cf8d2be0ad76a443345", 36, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r040", "cgtype5-stack-r040", "3fb7a6592a6bce26bf3e3a31e3a1b8b9f8f3e6d6c00ae6e43d109d0a845e9ef0", 40, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r044", "cgtype5-stack-r044", "55f4c904f3171117042ded9bbdc9c269fb9f3c007d27e519224192e4145333a7", 44, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r048", "cgtype5-stack-r048", "6505927b6c35faa003080de4cf5ef0615684536ee3582b8572199cd28c314334", 48, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r052", "cgtype5-stack-r052", "8625b33f35693565e60a3080b508be938665878b6c38caa19decef7a3cc4eb1d", 52, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r056", "cgtype5-stack-r056", "a6beabfe204b65d854f6158c3d50c942983eb259970a5767145f3beb4afd4b99", 56, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r060", "cgtype5-stack-r060", "612f6b48ad54600dab60dc91f5b74265e6d1def39788d802708fbd6e53816d10", 60, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r064", "cgtype5-stack-r064", "3f12d988b826fe269904128539d582b85d432a07533f39be1042b68b644d5ffd", 64, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r068", "cgtype5-stack-r068", "d12be172ce99c251aeedfbbf3407457142f874823a29592f1e6fb76e93acbed4", 68, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r072", "cgtype5-stack-r072", "c94ac65e49e161217505c88dbcfc08b8c2a2cb159ac0d00fff7372010118c1da", 72, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r076", "cgtype5-stack-r076", "ee6df39b99f26f80cae32dfc5de56816b7e4b8ae71dc1a97c5930f14f2f22233", 76, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r080", "cgtype5-stack-r080", "e8e6a74e525aac4218f29d4861131e88cbabc331fcb29fdbfdae02ff4503e387", 80, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r084", "cgtype5-stack-r084", "f3c1ed85566b3e8bce418f42e7531a2742accf0b6ba70046a0542d11ebaf7d33", 84, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r088", "cgtype5-stack-r088", "4de5750d49bbd9613a8127e4a9547ffd27c78da85d9cb8c4200c8e1ace779314", 88, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r092", "cgtype5-stack-r092", "69a93f315bc4291b9de74a1aadd282a7458914a820f562da34b0c34e89e9eda8", 92, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r096", "cgtype5-stack-r096", "e8ea35b8847ba9a012871103c0215cb3a0891103a373e253164c2a0719df6856", 96, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r100", "cgtype5-stack-r100", "532f0533d3ff5808c25ac9ca6897314dbf6778a9be94c355019b2e872390c215", 100, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r104", "cgtype5-stack-r104", "aa97607a0bd252a6fbbbd8669cdfd1d9d1c4a2289c6cbd8c14b80eaa568375f8", 104, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r108", "cgtype5-stack-r108", "f27b72e9fd497c38973c6e14d8cd8c4c2d5d99faf220cd1cf75f52239c4c9c38", 108, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r112", "cgtype5-stack-r112", "7b35d99280b6d74098d6d59c7f36a10f8fa671daf86a2be7b75169a3a59481e5", 112, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r116", "cgtype5-stack-r116", "22c8e648e1129dcf3e5bea3ed2c6593965fb0d7d82591c608e746ba926644a6c", 116, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r120", "cgtype5-stack-r120", "1010d85d5ccf612342cf4b02020a6622773fb8ad7a94d3ee605f2943716b102e", 120, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r124", "cgtype5-stack-r124", "f363f6fa44f9b367608274f8c9e2fd3607a0eddfc1e52dcdcd0ce42d98e46317", 124, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r128", "cgtype5-stack-r128", "2d4475543dc4c7bdd34c18e8fc58b1094b7839434f3d268567e8d2e79b39a3fb", 128, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r132", "cgtype5-stack-r132", "f14b8dcd01514989362fc4283ef77a77c85fa3ca396ff64bf070489171c4fc9a", 132, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r136", "cgtype5-stack-r136", "e03ebcfb8f075db0550b6cae2d773fba15cf4a57efda48d181c08c6368703c9d", 136, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r140", "cgtype5-stack-r140", "71581ba2f3647bbaf98ab227c8697e3aa496fe2daa4775d71c511a7af69e3023", 140, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r144", "cgtype5-stack-r144", "5cd3c72a3a3289a1f1229de9ea26ab2146877ec72b9f88dd4738205cd68368bf", 144, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r148", "cgtype5-stack-r148", "2c117eb59ee75fd667bf7573715501e3a8abe130603691436ddfe49731fe24d9", 148, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r152", "cgtype5-stack-r152", "289501528651760434b0b8385794c3c27a6618a4820d9d3062faf5d1752268b8", 152, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r156", "cgtype5-stack-r156", "d4a2748e738d843ce85e2452f3a57db90b0bd2ca5d056c429968e3bfbd9c166d", 156, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r160", "cgtype5-stack-r160", "1ffd42212ef825e3d8aa402f4117342fb3d234d3baa51d5eeea8b3ec1a1dc66a", 160, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r164", "cgtype5-stack-r164", "440f55a0c020efb1a4fc41252b17a8d40643cb9b5342c2095dba8817322b5886", 164, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r168", "cgtype5-stack-r168", "6ffec092fc874ad1eb9734665833feb127751b8be3f9bbfbe758111e035e2ed6", 168, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r172", "cgtype5-stack-r172", "cb715157cf681761facf5cbf3e7172b5063510c774c734618494579f1cad4d3d", 172, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r176", "cgtype5-stack-r176", "f353941190c9b063a3b24f404ce33c7d0d47b2e72a6da92c34a0ed8f617146cb", 176, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r180", "cgtype5-stack-r180", "8b74c4c91145f3cda1183a31ba6ee71d62607941f60de263014d45c9858b71a9", 180, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r184", "cgtype5-stack-r184", "d9778b75c1868e294f9e3fa38273306a4c4460de676b72f64b236a9c023db87f", 184, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r188", "cgtype5-stack-r188", "f91584d75adf1de9623170e337b76152b011a23025fce132721e5f04fcda49d8", 188, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r192", "cgtype5-stack-r192", "9f05b7a5dbbfbf0fb69a51df03107c6d52d7ac6365220f43817acc2490cf78f5", 192, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r196", "cgtype5-stack-r196", "a9bf9cbf16434c5dcb8da0e26d8c9c997bcf53252d28a7e80acdca6920716c2e", 196, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r200", "cgtype5-stack-r200", "0c37721b8f7e4dbe0f6d13b5a32b961a83a2556ed8dfe70c4e7f919a1a87c54c", 200, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r204", "cgtype5-stack-r204", "5c292552125b9f6c6d7a474f4936ef8dd3e0beaad7dd78ae81ece1e954818e99", 204, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r208", "cgtype5-stack-r208", "2aa2657d6e6f988ee7b6a0d2fca8d0314f4aff4e9554a842cdc8f7ef4ae76245", 208, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r212", "cgtype5-stack-r212", "649913720c7a281d4e67bf31a210d8233e34e2ec2e6e66544162bb9de30a7b53", 212, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r216", "cgtype5-stack-r216", "4b36d61d21289deed9abdbc7fa9994c4a2db353ee19679b1545af856629323ef", 216, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r220", "cgtype5-stack-r220", "d27b2f6d12852ab304d268f003afc8761337874afa13a90478d9e7d4ee248917", 220, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r224", "cgtype5-stack-r224", "199e8d2f0fe38051096c418b96516d60adef6168f6e1a39ff9710e90ec695ee6", 224, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r228", "cgtype5-stack-r228", "4eb76b0ec0d16ba86db42a9ff2cb9c1428f82c8e3ae183fc3cf00cf1f0312fde", 228, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r232", "cgtype5-stack-r232", "db40f0de55eae9572bebdc0bdd18a19183540529bc99e9e590e191174337a1a6", 232, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r236", "cgtype5-stack-r236", "4c0a78794d81b561061de98b33258e6f62ccf24e561ae7b34065372c02f32ef1", 236, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r240", "cgtype5-stack-r240", "7c5c6270234131409e9d3eb3e37f851730804a7349acd9449f6ba89eeccca109", 240, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r244", "cgtype5-stack-r244", "8362448b9adc61732d122163fda744c1f51dd18b28119ebb9b5d69229a2f8f80", 244, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r248", "cgtype5-stack-r248", "c101db6c8cfb410d625725a68dc2a89daf160b879c05a27bb0b09f38b04e3393", 248, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r252", "cgtype5-stack-r252", "156c1926a0bdfec740692e1dd421a7422d3fcfcf8ed8b30212d851cedc8b2178", 252, 1, 2, 2, 2, 0x1b0},
    {"type5-stack-r256", "cgtype5-stack-r256", "9461f60464b6321de1f55ce29c02069be00500825c0b2b46bcfa11f359d5459d", 256, 1, 2, 2, 2, 0x1b0},
};

static const NSUInteger KPCGType5StackVariantCount = sizeof(KPCGType5StackVariants) / sizeof(KPCGType5StackVariants[0]);

#endif
