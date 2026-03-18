// Official AFT Scoring Tables - Effective June 1, 2025
// Age bands: 0=17-21, 1=22-26, 2=27-31, 3=32-36, 4=37-41, 5=42-46, 6=47-51, 7=52-56, 8=57-61, 9=62+
// Each entry: [male_value, female_value] per age band
// For MDL: value = weight in lbs
// For HRP: value = reps
// For SDC: value = time string "M:SS"
// For PLK: value = time string "M:SS"
// For 2MR: value = time string "MM:SS"

const AGE_BANDS = ['17-21','22-26','27-31','32-36','37-41','42-46','47-51','52-56','57-61','62+'];

// MDL scoring table (lbs) - [M, F] per age band, indexed by points 0-100
const MDL = {
  100: [340,220, 350,230, 350,240, 350,230, 350,220, 350,210, 340,200, 330,190, 250,170, 230,170],
  99:  [null,null, 340,null, null,230, 340,220, 340,210, 340,null, 330,null, 320,null, 240,160, 220,160],
  98:  [330,210, null,220, 340,220, null,null, null,null, null,200, null,190, null,180, 230,null, 210,null],
  97:  [null,200, 330,210, 330,null, 330,210, 330,200, 330,null, 320,null, 310,null, 220,null, null,null],
  96:  [320,null, null,null, null,210, null,null, null,null, null,190, null,180, null,null, 210,null, null,null],
  95:  [null,null, 320,200, 320,200, 320,200, 320,190, 320,null, 310,null, 300,170, null,null, 200,null],
  94:  [310,190, null,null, null,null, null,null, null,null, null,null, null,null, null,null, 200,null, 190,null],
  93:  [null,null, 310,190, 310,null, 310,190, 310,null, 310,180, 300,170, 290,null, 190,null, 180,null],
  92:  [300,null, null,null, null,190, null,null, null,180, 300,null, null,null, null,null, null,null, 170,null],
  91:  [null,180, 300,null, 300,null, 300,null, 300,null, null,null, 290,null, 280,160, 180,null, null,null],
  90:  [null,null, null,null, null,null, null,180, null,null, 290,170, null,null, null,null, null,150, null,150],
  89:  [290,null, 290,180, 290,180, 290,null, 290,170, null,null, 280,160, 270,null, 170,null, null,null],
  88:  [null,170, null,null, null,null, null,null, null,null, 280,null, null,null, null,null, null,null, null,null],
  87:  [280,null, 280,null, 280,null, 280,170, 280,null, null,null, null,null, null,null, null,null, null,null],
  86:  [null,null, null,170, null,170, null,null, null,null, 270,160, 270,null, 260,null, null,null, null,null],
  85:  [270,null, 270,null, 270,null, 270,null, 270,160, null,null, null,null, null,150, null,null, null,null],
  84:  [null,160, null,null, null,null, null,null, null,null, 260,null, 260,150, 250,null, null,null, null,null],
  83:  [260,null, 260,null, 260,null, 260,160, 260,null, null,null, null,null, null,null, null,null, null,null],
  82:  [null,null, null,160, null,160, null,null, null,null, 250,150, 250,null, 240,null, null,null, 160,null],
  81:  [250,null, 250,null, 250,null, 250,null, 250,null, null,null, null,null, null,null, null,null, null,null],
  80:  [null,150, null,null, null,null, null,null, null,150, null,null, 240,null, 230,null, null,140, null,140],
  79:  [240,null, 240,null, 240,null, 240,150, 240,null, 240,null, null,140, null,140, 160,null, null,null],
  78:  [null,null, null,150, null,150, null,null, null,null, 230,null, 230,null, 220,null, null,null, null,null],
  77:  [230,null, 230,null, 230,null, 230,null, 230,null, null,null, null,null, null,null, null,null, null,null],
  76:  [null,null, null,null, null,null, null,null, null,null, 220,140, 220,null, 210,null, null,null, null,null],
  75:  [220,140, 220,null, 220,null, 220,null, 220,140, null,null, null,null, null,null, null,null, null,null],
  74:  [null,null, null,null, null,null, null,140, null,null, 210,null, 210,null, 200,null, null,null, null,null],
  73:  [210,null, 210,140, 210,140, 210,null, 210,null, null,null, null,130, null,null, null,null, null,null],
  72:  [null,null, null,null, null,null, null,null, null,null, 200,null, 200,null, 190,130, null,null, 150,130],
  71:  [null,null, 200,null, 200,null, 200,null, 200,null, null,null, null,null, null,null, 150,130, null,null],
  70:  [200,null, 190,null, 190,null, 190,null, 190,null, 190,130, 190,null, 180,null, null,null, null,null],
  60:  [150,120, 150,120, 150,120, 140,120, 140,120, 140,120, 140,120, 140,120, 140,120, 140,120],
  50:  [130,110, 130,110, 130,110, 130,110, 130,110, 130,110, 130,110, 130,110, 130,110, 130,110],
  40:  [120,100, 120,100, 120,100, 120,100, 120,100, 120,100, 120,100, 120,100, 120,100, 120,100],
  30:  [110,90, 110,90, 110,90, 110,90, 110,90, 110,90, 110,90, 110,90, 110,90, 110,90],
  20:  [100,80, 100,80, 100,80, 100,80, 100,80, 100,80, 100,80, 100,80, 100,80, 100,80],
  10:  [90,70, 90,70, 90,70, 90,70, 90,70, 90,70, 90,70, 90,70, 90,70, 90,70],
  0:   [80,60, 80,60, 80,60, 80,60, 80,60, 80,60, 80,60, 80,60, 80,60, 80,60],
};

// HRP scoring table (reps) - [M, F] per age band
const HRP = {
  100: [58,53, 61,50, 62,48, 60,47, 59,43, 57,40, 55,38, 51,36, 46,24, 43,24],
  95:  [52,38, 53,39, 54,39, 53,38, 51,35, 49,33, 48,32, 45,30, 35,19, 34,19],
  90:  [46,32, 48,33, 48,33, 47,32, 46,30, 44,29, 42,null, 40,26, 29,15, 26,15],
  85:  [41,27, 42,28, 43,28, 42,27, 40,26, 39,null, 37,null, 35,22, null,null, 22,null],
  80:  [37,23, 37,23, 37,23, 36,23, 35,22, 34,21, 32,20, 30,19, 18,null, 17,null],
  75:  [32,null, 31,null, 32,null, 31,19, 30,null, 29,18, 27,17, null,null, 15,null, null,null],
  70:  [28,18, 26,16, 26,16, 26,16, 24,null, 23,15, 22,null, 21,14, null,null, null,null],
  65:  [22,null, 21,13, 21,null, 20,13, 19,13, 18,null, 17,null, 16,12, 11,null, null,null],
  60:  [15,11, 14,11, 14,11, 13,11, 12,10, 11,10, 11,10, 10,10, 10,10, 10,10],
  50:  [9,9, 9,9, 9,9, 9,9, 9,9, 9,9, 9,9, 9,9, 9,9, 9,9],
  40:  [8,8, 8,8, 8,8, 8,8, 8,8, 8,8, 8,8, 8,8, 8,8, 8,8],
  30:  [7,7, 7,7, 7,7, 7,7, 7,7, 7,7, 7,7, 7,7, 7,7, 7,7],
  20:  [6,6, 6,6, 6,6, 6,6, 6,6, 6,6, 6,6, 6,6, 6,6, 6,6],
  10:  [5,5, 5,5, 5,5, 5,5, 5,5, 5,5, 5,5, 5,5, 5,5, 5,5],
  0:   [4,4, 4,4, 4,4, 4,4, 4,4, 4,4, 4,4, 4,4, 4,4, 4,4],
};

// SDC scoring table (time M:SS - lower is better)
const SDC = {
  100: ['1:29','1:55', '1:30','1:55', '1:30','1:55', '1:33','1:59', '1:36','2:02', '1:40','2:09', '1:45','2:11', '1:52','2:18', '1:58','2:26', '2:09','2:26'],
  90:  ['1:43','2:16', '1:43','2:15', '1:45','2:16', '1:48','2:20', '1:52','2:25', '1:56','2:30', '2:02','2:37', '2:10','2:44', '2:17','2:54', null,'2:54'],
  80:  ['1:53','2:28', '1:53','2:29', '1:55','2:29', '1:58','2:34', '2:02','2:38', '2:07','2:44', '2:14','2:50', '2:23','2:58', '2:29','3:07', '2:32','3:07'],
  70:  ['2:03','2:41', '2:05','2:43', '2:06','2:43', '2:10','2:47', '2:14','2:52', '2:20','2:58', '2:27','3:05', '2:35','3:19', '2:43','3:36', '2:49','3:36'],
  60:  ['2:28','3:15', '2:31','3:15', '2:32','3:15', '2:36','3:22', '2:41','3:27', '2:45','3:42', '2:53','3:51', '3:00','4:03', '3:12','4:48', '3:16','4:48'],
};

// PLK scoring table (time M:SS - higher is better)
const PLK = {
  100: ['3:40','3:40', '3:35','3:35', '3:30','3:30', '3:25','3:25', '3:20','3:20', '3:20','3:20', '3:20','3:20', '3:20','3:20', '3:20','3:20', '3:20','3:20'],
  90:  ['3:08','3:08', '3:03','3:03', '2:58','2:58', '2:53','2:53', '2:47','2:47', '2:47','2:47', '2:47','2:47', '2:47','2:47', '2:47','2:47', '2:47','2:47'],
  80:  ['2:35','2:35', '2:30','2:30', '2:25','2:25', '2:20','2:20', '2:15','2:15', '2:15','2:15', '2:15','2:15', '2:15','2:15', '2:15','2:15', '2:15','2:15'],
  70:  ['2:02','2:02', '1:58','1:58', '1:52','1:52', '1:47','1:47', '1:42','1:42', '1:42','1:42', '1:42','1:42', '1:42','1:42', '1:42','1:42', '1:42','1:42'],
  60:  ['1:30','1:30', '1:25','1:25', '1:20','1:20', '1:15','1:15', '1:10','1:10', '1:10','1:10', '1:10','1:10', '1:10','1:10', '1:10','1:10', '1:10','1:10'],
  50:  ['1:25','1:25', '1:20','1:20', '1:15','1:15', '1:10','1:10', '1:05','1:05', '1:05','1:05', '1:05','1:05', '1:05','1:05', '1:05','1:05', '1:05','1:05'],
  40:  ['1:20','1:20', '1:15','1:15', '1:10','1:10', '1:05','1:05', '1:00','1:00', '1:00','1:00', '1:00','1:00', '1:00','1:00', '1:00','1:00', '1:00','1:00'],
  30:  ['1:15','1:15', '1:10','1:10', '1:05','1:05', '1:00','1:00', '0:55','0:55', '0:55','0:55', '0:55','0:55', '0:55','0:55', '0:55','0:55', '0:55','0:55'],
  20:  ['1:10','1:10', '1:05','1:05', '1:00','1:00', '0:55','0:55', '0:50','0:50', '0:50','0:50', '0:50','0:50', '0:50','0:50', '0:50','0:50', '0:50','0:50'],
  10:  ['1:05','1:05', '1:00','1:00', '0:55','0:55', '0:50','0:50', '0:45','0:45', '0:45','0:45', '0:45','0:45', '0:45','0:45', '0:45','0:45', '0:45','0:45'],
  0:   ['1:00','1:00', '0:55','0:55', '0:50','0:50', '0:45','0:45', '0:40','0:40', '0:40','0:40', '0:40','0:40', '0:40','0:40', '0:40','0:40', '0:40','0:40'],
};

// 2MR scoring table (time MM:SS - lower is better)
const TMR = {
  100: ['13:22','16:00', '13:25','15:30', '13:25','15:30', '13:42','15:48', '13:42','15:51', '14:05','16:00', '14:30','16:30', '15:09','16:59', '15:28','17:18', '15:28','17:18'],
  90:  ['15:39','17:55', '15:38','17:44', '15:38','17:44', '15:50','18:21', '16:01','18:25', '16:15','18:37', '16:39','19:03', '17:26','19:47', '18:17','20:26', '18:17','20:26'],
  80:  ['17:13','19:30', null,'19:25', '17:21','19:45', '17:16','19:53', '17:33','19:57', '17:47','20:10', '18:12','20:34', '19:00','21:19', '19:45','21:51', '19:45','21:59'],
  70:  ['18:35','21:06', '18:23','21:00', '18:23','21:00', '18:30','21:13', '18:35','21:16', '18:55','21:30', '19:30','21:45', '20:20','22:38', '21:00','23:11', '21:00','23:20'],
  60:  ['19:57','22:55', '19:45','22:45', '19:45','22:45', '20:44','22:50', '20:44','22:59', '22:04','23:15', '22:04','23:30', '22:50','24:00', '23:36','24:48', '23:36','25:00'],
  50:  ['20:25','23:24', '20:13','23:14', '20:13','23:14', '21:12','23:19', '21:12','23:28', '22:32','23:44', '22:32','23:59', '23:18','24:29', '24:04','25:17', '24:04','25:29'],
  40:  ['20:53','23:53', '20:41','23:43', '20:41','23:43', '21:40','23:48', '21:40','23:57', '23:00','24:13', '23:00','24:28', '23:46','24:58', '24:32','25:46', '24:32','25:58'],
  30:  ['21:21','24:22', '21:09','24:12', '21:09','24:12', '22:08','24:17', '22:08','24:26', '23:28','24:42', '23:28','24:57', '24:14','25:27', '25:00','26:15', '25:00','26:27'],
  20:  ['21:49','24:51', '21:37','24:41', '21:37','24:41', '22:36','24:46', '22:36','24:55', '23:56','25:11', '23:56','25:26', '24:42','25:56', '25:28','26:44', '25:28','26:56'],
  10:  ['22:17','25:20', '22:05','25:10', '22:05','25:10', '23:04','25:15', '23:04','25:24', '24:24','25:40', '24:24','25:55', '25:10','26:25', '25:56','27:13', '25:56','27:25'],
  0:   ['22:45','25:50', '22:33','25:40', '22:33','25:40', '23:32','25:45', '23:32','25:54', '24:52','26:10', '24:52','26:25', '25:38','26:55', '26:24','27:43', '26:24','27:55'],
};

function getAgeBandIndex(age) {
  const bands = [21, 26, 31, 36, 41, 46, 51, 56, 61];
  for (let i = 0; i < bands.length; i++) {
    if (age <= bands[i]) return i;
  }
  return 9;
}

function timeToSeconds(t) {
  if (!t || t === '---') return null;
  const parts = t.split(':');
  return parseInt(parts[0]) * 60 + parseInt(parts[1]);
}

// Score MDL (higher weight = higher score, interpolate between breakpoints)
function scoreMDL(weightLbs, age, sex) {
  const bandIdx = getAgeBandIndex(age);
  const colIdx = bandIdx * 2 + (sex === 'F' ? 1 : 0);
  const points = Object.keys(MDL).map(Number).sort((a,b) => b - a);
  
  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    const val = MDL[pt][colIdx];
    if (val === null) continue;
    if (weightLbs >= val) return pt;
  }
  return 0;
}

// Score HRP (higher reps = higher score)
function scoreHRP(reps, age, sex) {
  const bandIdx = getAgeBandIndex(age);
  const colIdx = bandIdx * 2 + (sex === 'F' ? 1 : 0);
  const points = Object.keys(HRP).map(Number).sort((a,b) => b - a);
  
  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    const val = HRP[pt][colIdx];
    if (val === null) continue;
    if (reps >= val) return pt;
  }
  return 0;
}

// Score SDC (lower time = higher score)
function scoreSDC(timeStr, age, sex) {
  const bandIdx = getAgeBandIndex(age);
  const colIdx = bandIdx * 2 + (sex === 'F' ? 1 : 0);
  const inputSecs = timeToSeconds(timeStr);
  if (!inputSecs) return 0;
  
  const points = Object.keys(SDC).map(Number).sort((a,b) => b - a);
  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    const val = SDC[pt][colIdx];
    if (!val) continue;
    const valSecs = timeToSeconds(val);
    if (inputSecs <= valSecs) return pt;
  }
  return 0;
}

// Score PLK (higher time = higher score)
function scorePLK(timeStr, age, sex) {
  const bandIdx = getAgeBandIndex(age);
  const colIdx = bandIdx * 2 + (sex === 'F' ? 1 : 0);
  const inputSecs = timeToSeconds(timeStr);
  if (!inputSecs) return 0;
  
  const points = Object.keys(PLK).map(Number).sort((a,b) => b - a);
  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    const val = PLK[pt][colIdx];
    if (!val) continue;
    const valSecs = timeToSeconds(val);
    if (inputSecs >= valSecs) return pt;
  }
  return 0;
}

// Score 2MR (lower time = higher score)
function score2MR(timeStr, age, sex) {
  const bandIdx = getAgeBandIndex(age);
  const colIdx = bandIdx * 2 + (sex === 'F' ? 1 : 0);
  const inputSecs = timeToSeconds(timeStr);
  if (!inputSecs) return 0;
  
  const points = Object.keys(TMR).map(Number).sort((a,b) => b - a);
  for (let i = 0; i < points.length; i++) {
    const pt = points[i];
    const val = TMR[pt][colIdx];
    if (!val) continue;
    const valSecs = timeToSeconds(val);
    if (inputSecs <= valSecs) return pt;
  }
  return 0;
}

function calculateAFT(data) {
  const { age, sex, standard, mdl, hrp, sdc, plk, tmr } = data;
  
  const scores = {
    mdl: scoreMDL(parseInt(mdl), parseInt(age), sex),
    hrp: scoreHRP(parseInt(hrp), parseInt(age), sex),
    sdc: scoreSDC(sdc, parseInt(age), sex),
    plk: scorePLK(plk, parseInt(age), sex),
    tmr: score2MR(tmr, parseInt(age), sex),
  };
  
  const total = Object.values(scores).reduce((a,b) => a + b, 0);
  const minPerEvent = 60;
  const minTotal = standard === 'combat' ? 350 : 300;
  
  const eventPass = Object.values(scores).every(s => s >= minPerEvent);
  const totalPass = total >= minTotal;
  const overallPass = eventPass && totalPass;
  
  return { scores, total, overallPass, eventPass, totalPass, minTotal };
}

module.exports = { calculateAFT, getAgeBandIndex };
