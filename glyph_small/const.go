package glyph_small

const (
	PKSize  = qBits * constN / 8                  //512 bytes
	SKSize  = 2 * 2 * constN / 8                  //1792 bytes
	SigSize = ((bBits+1+2)*constN + 11*omega) / 8 //1942 bytes
)

const (
	glpDigestLength = uint32(32)

	constN = uint32(1024)
	nBits  = uint32(10)
	omega  = uint32(16)

	//sk:512 bytes,pk:2048 bytes, sig:2198bytes
	//4246 bytes
	// constQ = 59393
	// constB = 16383
	// bBits  = 14
	// qBits  = 16

	//sk:512 bytes,pk:1792 bytes, sig:1942 bytes
	//3737 bytes
	constQ = uint32(12289)
	constB = uint32(4095)
	bBits  = uint32(12)
	qBits  = uint32(14)
)

/*var Pi60 = []uint32{576460752308273153, 576460752315482113, 576460752319021057, 576460752319414273, 576460752321642497,
576460752325705729, 576460752328327169, 576460752329113601, 576460752329506817, 576460752329900033,
576460752331210753, 576460752337502209, 576460752340123649, 576460752342876161, 576460752347201537,
576460752347332609, 576460752352837633, 576460752354017281, 576460752355065857, 576460752355459073,
576460752358604801, 576460752364240897, 576460752368435201, 576460752371187713, 576460752373547009,
576460752374333441, 576460752376692737, 576460752378003457, 576460752378396673, 576460752380755969,
576460752381411329, 576460752386129921, 576460752395173889, 576460752395960321, 576460752396091393,
576460752396484609, 576460752399106049, 576460752405135361, 576460752405921793, 576460752409722881,
576460752410116097, 576460752411033601, 576460752412082177, 576460752416145409, 576460752416931841,
576460752421257217, 576460752427548673, 576460752429514753, 576460752435281921, 576460752437248001,
576460752438558721, 576460752441966593, 576460752449044481, 576460752451141633, 576460752451534849,
576460752462938113, 576460752465952769, 576460752468705281, 576460752469491713, 576460752472375297,
576460752473948161, 576460752475389953, 576460752480894977, 576460752483254273, 576460752484827137,
576460752486793217, 576460752486924289, 576460752492691457, 576460752498589697, 576460752498720769,
576460752499507201, 576460752504225793, 576460752505405441, 576460752507240449, 576460752507764737,
576460752509206529, 576460752510124033, 576460752510779393, 576460752511959041, 576460752514449409,
576460752516284417, 576460752519168001, 576460752520347649, 576460752520609793, 576460752522969089,
576460752523100161, 576460752524279809, 576460752525852673, 576460752526245889, 576460752526508033,
576460752532013057, 576460752545120257, 576460752550100993, 576460752551804929, 576460752567402497,
576460752568975361, 576460752573431809, 576460752580902913, 576460752585490433, 576460752586407937}*/

// Last hundred (from 0xfffffffffffffff and downward) 60bit Primes allowing ǸTT for N = 65536
/*var Qi60 = []uint32{1152921504606584833, 1152921504598720513, 1152921504592429057, 1152921504581419009, 1152921504580894721,
1152921504578273281, 1152921504577748993, 1152921504577486849, 1152921504568836097, 1152921504565166081,
1152921504563331073, 1152921504556515329, 1152921504555466753, 1152921504554156033, 1152921504552583169,
1152921504542883841, 1152921504538951681, 1152921504537378817, 1152921504531873793, 1152921504521650177,
1152921504509853697, 1152921504508280833, 1152921504506970113, 1152921504495697921, 1152921504491241473,
1152921504488620033, 1152921504479444993, 1152921504470794241, 1152921504468172801, 1152921504462929921,
1152921504462667777, 1152921504455589889, 1152921504447987713, 1152921504442482689, 1152921504436191233,
1152921504427278337, 1152921504419414017, 1152921504409190401, 1152921504403947521, 1152921504396869633,
1152921504395821057, 1152921504373014529, 1152921504369344513, 1152921504368558081, 1152921504364625921,
1152921504362790913, 1152921504361218049, 1152921504353615873, 1152921504337887233, 1152921504337625089,
1152921504321372161, 1152921504314032129, 1152921504303022081, 1152921504301449217, 1152921504288342017,
1152921504287293441, 1152921504286769153, 1152921504282836993, 1152921504274972673, 1152921504266321921,
1152921504256622593, 1152921504253739009, 1152921504245088257, 1152921504241942529, 1152921504240107521,
1152921504239583233, 1152921504238010369, 1152921504234078209, 1152921504231718913, 1152921504230670337,
1152921504227524609, 1152921504214417409, 1152921504207339521, 1152921504205504513, 1152921504204193793,
1152921504190824449, 1152921504179552257, 1152921504177192961, 1152921504176668673, 1152921504174309377,
1152921504172474369, 1152921504164872193, 1152921504162512897, 1152921504139706369, 1152921504134987777,
1152921504132628481, 1152921504122142721, 1152921504120832001, 1152921504116899841, 1152921504105627649,
1152921504101957633, 1152921504100384769, 1152921504096452609, 1152921504093306881, 1152921504078364673,
1152921504067092481, 1152921504066306049, 1152921504057917441, 1152921504053723137, 1152921504050839553}*/

var constA = [constN]uint32{
	12024, 932, 10104, 159, 1786, 2695, 11945, 4563, 11128, 11544, 2492, 12032, 2245, 2263, 8076, 8793, 613, 1056, 6039, 8641, 10440, 5742, 4507, 1768, 7344, 1777, 7308, 11089, 5232, 9562, 998, 5897, 7642,
	720, 3514, 2813, 1525, 4104, 1569, 10099, 8879, 3977, 3252, 5196, 1428, 2320, 1474, 12160, 8109, 9009, 5077, 9399, 9400, 1211, 12111, 10887, 5512, 8901, 10741, 9016, 1353, 3465, 4582, 3272, 2606,
	1189, 4165, 633, 11075, 9826, 203, 11732, 3114, 947, 11912, 7012, 7007, 9597, 9645, 1432, 11015, 10293, 1076, 11552, 2246, 5930, 438, 8428, 3468, 6878, 4923, 5212, 8289, 2740, 868, 8494, 6321,
	4560, 8470, 454, 8234, 11718, 491, 2281, 6192, 10754, 3403, 7346, 371, 10187, 1383, 4556, 11258, 2536, 11194, 7285, 4522, 1046, 1377, 12059, 8388, 5432, 11644, 4847, 10535, 12151, 7329, 395, 11489,
	11698, 1828, 828, 2648, 10627, 10052, 4341, 5220, 52, 1022, 5562, 2918, 4924, 5768, 5728, 6182, 7267, 521, 6506, 7610, 10919, 113, 4945, 3875, 6098, 6313, 11032, 3523, 8134, 1778, 8155, 5508,
	9743, 7265, 5141, 9036, 3807, 1363, 5888, 2381, 3271, 9293, 10354, 10658, 10833, 9868, 1649, 4272, 9433, 10051, 10710, 4449, 9164, 8513, 11871, 9537, 9893, 5908, 10024, 12070, 10977, 2045, 5886, 10733,
	7416, 9382, 83, 5710, 8407, 3753, 7576, 9799, 924, 7988, 9468, 10936, 5636, 4650, 1202, 7545, 397, 10022, 5558, 5000, 6508, 6803, 8527, 11773, 5245, 10726, 2702, 2223, 11003, 10345, 6766, 8974,
	1616, 11320, 143, 9928, 727, 8814, 1822, 8566, 10684, 316, 6895, 11088, 5437, 5374, 1024, 417, 773, 546, 10770, 10072, 9369, 10605, 4307, 9627, 7018, 2503, 7890, 7630, 10207, 9042, 6857, 8210,
	1165, 11521, 7826, 10479, 6639, 8664, 11020, 1485, 3051, 162, 2768, 2131, 296, 4980, 11800, 6580, 5559, 5395, 6752, 1273, 2847, 3188, 3488, 6712, 10203, 5294, 288, 7212, 1588, 4030, 7522, 9451,
	4494, 6096, 1292, 965, 4446, 9213, 11417, 9434, 8486, 9987, 8475, 2152, 11574, 11639, 8109, 2685, 3874, 4820, 1269, 883, 9086, 8795, 4817, 7775, 11864, 3616, 9658, 4247, 8779, 10687, 6439, 2010,
	5827, 10229, 11104, 9054, 4003, 3664, 4020, 10569, 10501, 9864, 7401, 547, 153, 9509, 9811, 10326, 3583, 8817, 4069, 879, 5299, 8054, 2005, 3899, 11298, 4212, 9130, 9687, 6900, 8974, 6771, 5926,
	10373, 10178, 2922, 7219, 984, 6546, 8337, 3431, 11032, 12034, 8152, 7779, 10464, 4704, 7646, 10043, 9606, 1969, 1275, 3094, 9945, 5869, 3098, 2834, 2787, 11894, 5142, 11512, 1522, 4123, 7688, 11864,
	9976, 10717, 6882, 7279, 314, 812, 2501, 8118, 6769, 10608, 1289, 1689, 9507, 172, 10191, 8932, 11548, 2829, 7048, 9648, 9499, 2628, 7686, 5195, 10939, 6632, 11840, 12260, 7346, 2015, 1476, 1682,
	1748, 3185, 915, 6585, 11310, 10751, 10755, 2428, 2885, 7253, 1963, 12215, 7814, 6706, 534, 2065, 2587, 2947, 3108, 5051, 3184, 8886, 1916, 3518, 7906, 2230, 9597, 6989, 9701, 1035, 4277, 6764,
	314, 11531, 4689, 11298, 3746, 11808, 9760, 7937, 11459, 2049, 5078, 5714, 3539, 11377, 10300, 12287, 4487, 11109, 4297, 10425, 5983, 9276, 9129, 12191, 10353, 6863, 4628, 6092, 6724, 360, 2058, 3385,
	9318, 12279, 1115, 6116, 905, 412, 10749, 8738, 9265, 7515, 4762, 8550, 7040, 9217, 2296, 2797, 1490, 1395, 11232, 7553, 4460, 6126, 2961, 589, 4727, 10857, 3512, 3769, 2722, 6552, 4305, 2834,
	3794, 10894, 9721, 2464, 428, 1935, 9637, 3243, 1459, 6201, 9567, 8215, 7917, 8359, 5928, 1704, 1059, 4851, 6368, 11584, 7959, 437, 1311, 533, 10516, 5549, 9676, 2877, 11718, 1254, 10901, 3195,
	4016, 6352, 4790, 5763, 5490, 1801, 3625, 6100, 3763, 12006, 5414, 5648, 6292, 8460, 1659, 4702, 1242, 3418, 6714, 9770, 9594, 6829, 7044, 7784, 9108, 11577, 4769, 7769, 11360, 11965, 1470, 7321,
	662, 980, 7458, 8158, 3713, 1445, 157, 10662, 1586, 2562, 10121, 8988, 594, 2663, 10590, 856, 6074, 7401, 11351, 5536, 1402, 5672, 5413, 3306, 176, 5623, 870, 2209, 6947, 7163, 4865, 9063,
	5533, 9050, 7938, 7587, 1428, 603, 6267, 8905, 4696, 6745, 838, 2776, 6029, 3941, 6532, 266, 6934, 3, 3450, 5726, 10294, 8215, 1634, 2911, 11957, 11522, 4518, 7969, 3581, 4680, 588, 7761,
	10603, 9219, 1060, 3437, 2314, 8593, 2537, 12126, 2297, 8075, 11395, 10243, 2283, 4309, 3375, 4255, 2396, 1210, 610, 12119, 8199, 10793, 2238, 1370, 8164, 9456, 7708, 12028, 8576, 872, 4452, 4071,
	9719, 1176, 10207, 8203, 7138, 4028, 10218, 11670, 930, 11556, 3900, 10855, 6065, 10809, 2638, 1592, 7258, 5664, 5627, 270, 3072, 235, 12194, 514, 5839, 91, 8035, 699, 2788, 9787, 914, 11171,
	10132, 4722, 10850, 5208, 7512, 4201, 10064, 4126, 892, 5906, 3073, 10464, 1441, 2495, 6830, 5815, 8399, 12096, 2624, 4776, 8285, 10315, 6736, 7184, 8541, 9543, 9237, 7433, 8318, 4268, 11296, 9112,
	10510, 2787, 11199, 9964, 784, 1288, 5125, 8913, 10754, 1222, 3953, 9444, 9331, 2664, 6798, 3761, 3542, 815, 6010, 6914, 10498, 1330, 2121, 4061, 7612, 642, 1831, 6621, 5224, 5595, 3071, 4833,
	3249, 8597, 7142, 8253, 9043, 6030, 7028, 9124, 6353, 8802, 7839, 10616, 8906, 7544, 1298, 6991, 10754, 9525, 7133, 8000, 260, 499, 9121, 609, 1948, 288, 7825, 8908, 8656, 709, 11782, 2504,
	1896, 5917, 3845, 8345, 2034, 5587, 8025, 9353, 428, 2149, 3501, 2577, 8004, 525, 11512, 10946, 2885, 11976, 7512, 4133, 1801, 2034, 7775, 10802, 3307, 2058, 8019, 11751, 10801, 1950, 6291, 9761,
	3514, 3395, 8693, 9276, 11978, 245, 1266, 1928, 8370, 8600, 1491, 2981, 10450, 995, 10605, 4222, 10306, 761, 10498, 7044, 8614, 4273, 3031, 7108, 11297, 6946, 6735, 11303, 3596, 1164, 11999, 638,
	1679, 2526, 11586, 5449, 11693, 1426, 2493, 9220, 7061, 2162, 5438, 3922, 5768, 8284, 5328, 5802, 4720, 11141, 9607, 6657, 5856, 2759, 1455, 2445, 1272, 7376, 9982, 2709, 10043, 1326, 9552, 8779,
	3421, 3795, 132, 3321, 1058, 5755, 5535, 8004, 7403, 1228, 1637, 7551, 1217, 9676, 1930, 4736, 2631, 7073, 1143, 6905, 2146, 1865, 7590, 3215, 5851, 4968, 11220, 5149, 10094, 10671, 10133, 12045,
	7378, 4384, 8019, 9126, 11858, 9292, 3574, 9572, 9214, 9306, 578, 7079, 10555, 8480, 1015, 5325, 4508, 5889, 8095, 2034, 1815, 908, 12106, 5662, 11378, 6774, 6650, 4742, 1448, 6911, 12110, 9916,
	2039, 10380, 5697, 12272, 3767, 10001, 2221, 6889, 3319, 5960, 8773, 4514, 1064, 11821, 423, 9100, 11626, 10031, 7542, 1205, 4764, 7570, 6929, 8244, 10526, 9812, 845, 11167, 10257, 7577, 7726, 10540,
	5260, 2238, 4660, 10997, 12080, 8859, 4584, 633, 8956, 8163, 3077, 7808, 2027, 9012, 7562, 79, 577, 204, 10237, 8295, 4209, 2108, 7257, 12253, 12026, 12024, 7479, 908, 5598, 5150, 1767,
}
