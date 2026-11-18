// Dataset Bệnh viện Đa khoa: dữ liệu + 20 luật chuẩn + 30 ca kiểm thử (benchmark)
// ---------- Dataset thực tế: Bệnh viện Đa khoa (dùng trong mục "Nạp dữ liệu → Dữ liệu mẫu") ----------
const HOSPITAL_DATA = {
  benhNhan: [
    { _id: 'bn001', tenHo: 'Nguyễn Văn An', ngaySinh: '1985-03-15', gioiTinh: 'Nam', cccd: '079085012345', sdt: '0901234567', diaChi: '123 Lê Lợi, Q1, TP.HCM', nhomMau: 'A+', baoHiemYTe: 'VN84201234567' },
    { _id: 'bn002', tenHo: 'Trần Thị Bình', ngaySinh: '1992-07-22', gioiTinh: 'Nữ', cccd: '079092098765', sdt: '0912345678', diaChi: '456 Nguyễn Trãi, Q5, TP.HCM', nhomMau: 'O+', baoHiemYTe: 'VN84209876543' },
    { _id: 'bn003', tenHo: 'Lê Minh Châu', ngaySinh: '1978-11-30', gioiTinh: 'Nam', cccd: '079078054321', sdt: '0923456789', diaChi: '789 Đinh Tiên Hoàng, Q3, TP.HCM', nhomMau: 'B-', baoHiemYTe: 'VN84205432109' }
  ],
  hoSoBenhAn: [
    { _id: 'hs001', benhNhanId: 'bn001', bacSiId: 'bs001', ngayKham: '2024-01-15', trieuChung: 'Đau đầu, chóng mặt', chanDoan: 'Tăng huyết áp độ I', phuongPhapDieuTri: 'Thuốc + thay đổi lối sống', ketQuaXetNghiem: { huyetAp: '150/95', nhipTim: 78 } },
    { _id: 'hs002', benhNhanId: 'bn002', bacSiId: 'bs002', ngayKham: '2024-01-20', trieuChung: 'Ho kéo dài, sốt nhẹ', chanDoan: 'Viêm phế quản cấp', phuongPhapDieuTri: 'Kháng sinh + nghỉ ngơi', ketQuaXetNghiem: { nhietDo: 37.8, bachCau: 11000 } }
  ],
  donthuoc: [
    { _id: 'dt001', hoSoId: 'hs001', benhNhanId: 'bn001', bacSiKe: 'bs001', ngayKe: '2024-01-15', thuoc: [{ ten: 'Amlodipine 5mg', lieuLuong: '1 lần/ngày', soNgay: 30 }, { ten: 'Captopril 25mg', lieuLuong: '2 lần/ngày', soNgay: 30 }] },
    { _id: 'dt002', hoSoId: 'hs002', benhNhanId: 'bn002', bacSiKe: 'bs002', ngayKe: '2024-01-20', thuoc: [{ ten: 'Amoxicillin 500mg', lieuLuong: '3 lần/ngày', soNgay: 7 }] }
  ],
  lichHen: [
    { _id: 'lh001', benhNhanId: 'bn001', bacSiId: 'bs001', ngayHen: '2024-02-15T09:00:00', loaiKham: 'Tái khám', trangThai: 'Đã xác nhận', phong: 'P201' },
    { _id: 'lh002', benhNhanId: 'bn003', bacSiId: 'bs001', ngayHen: '2024-02-15T10:30:00', loaiKham: 'Khám mới', trangThai: 'Chờ', phong: 'P201' }
  ],
  nhanVien: [
    { _id: 'bs001', tenHo: 'BS. Phạm Quốc Dũng', chucVu: 'Trưởng khoa Nội', khoa: 'Nội khoa', luong: 25000000, bangCap: 'Tiến sĩ Y khoa', namKinhNghiem: 15 },
    { _id: 'bs002', tenHo: 'BS. Nguyễn Thị Lan', chucVu: 'Bác sĩ điều trị', khoa: 'Hô hấp', luong: 18000000, bangCap: 'Thạc sĩ Y khoa', namKinhNghiem: 8 }
  ],
  thuoc: [
    { _id: 'th001', ten: 'Amlodipine 5mg', nhasx: 'Pfizer', loai: 'Tim mạch', gia: 15000, tonKho: 500, donVi: 'Viên', hanDung: '2026-12-31' },
    { _id: 'th002', ten: 'Amoxicillin 500mg', nhasx: 'Mekophar', loai: 'Kháng sinh', gia: 5000, tonKho: 1000, donVi: 'Viên', hanDung: '2025-12-31' }
  ]
};

// 20 luật chuẩn soạn tay cho dataset bệnh viện (chỉ dùng khi nạp mẫu Bệnh viện)
const HOSPITAL_GT = [
  { id:'gt01', subject:['role=admin'], object:'*', actions:['*'], permission:'grant', reason:'Admin toàn quyền hệ thống', condition:'' },
  { id:'gt02', subject:['role=bacsi'], object:'hoSoBenhAn', actions:['read','write'], permission:'grant', reason:'Bác sĩ đọc/ghi hồ sơ bệnh án', condition:'' },
  { id:'gt03', subject:['role=bacsi'], object:'donthuoc', actions:['read','write'], permission:'grant', reason:'Bác sĩ kê đơn thuốc', condition:'' },
  { id:'gt04', subject:['role=bacsi'], object:'benhNhan', actions:['read'], permission:'grant', reason:'Bác sĩ xem thông tin bệnh nhân', condition:'' },
  { id:'gt05', subject:['role=bacsi'], object:'lichHen', actions:['read','write'], permission:'grant', reason:'Bác sĩ quản lý lịch hẹn', condition:'' },
  { id:'gt06', subject:['role=yta'], object:'benhNhan', actions:['read'], permission:'grant', reason:'Y tá xem thông tin bệnh nhân', condition:'' },
  { id:'gt07', subject:['role=yta'], object:'lichHen', actions:['read','write'], permission:'grant', reason:'Y tá quản lý lịch hẹn', condition:'' },
  { id:'gt08', subject:['role=yta'], object:'hoSoBenhAn', actions:['read'], permission:'grant', reason:'Y tá chỉ được đọc hồ sơ', condition:'' },
  { id:'gt09', subject:['role=yta'], object:'hoSoBenhAn/*/chanDoan', actions:['read','write'], permission:'deny', reason:'Y tá không được xem/sửa chẩn đoán', condition:'' },
  { id:'gt10', subject:['role=benhnhan'], object:'benhNhan/*/tenHo', actions:['read'], permission:'grant', reason:'Bệnh nhân xem tên của mình', condition:'' },
  { id:'gt11', subject:['role=benhnhan'], object:'lichHen', actions:['read'], permission:'grant', reason:'Bệnh nhân xem lịch hẹn', condition:'' },
  { id:'gt12', subject:['role=benhnhan'], object:'hoSoBenhAn', actions:['read','write','delete'], permission:'deny', reason:'Bệnh nhân không được vào hồ sơ bệnh án', condition:'' },
  { id:'gt13', subject:['role=duoc'], object:'donthuoc', actions:['read'], permission:'grant', reason:'Dược sĩ xem đơn thuốc', condition:'' },
  { id:'gt14', subject:['role=duoc'], object:'thuoc', actions:['read','write'], permission:'grant', reason:'Dược sĩ quản lý kho thuốc', condition:'' },
  { id:'gt15', subject:['role=user'], object:'benhNhan/*/cccd', actions:['read','write'], permission:'deny', reason:'Bảo vệ CCCD (thông tin nhạy cảm)', condition:'' },
  { id:'gt16', subject:['role=user'], object:'benhNhan/*/sdt', actions:['read'], permission:'deny', reason:'Bảo vệ SĐT (thông tin nhạy cảm)', condition:'' },
  { id:'gt17', subject:['role=admin'], object:'audit', actions:['read'], permission:'grant', reason:'Chỉ admin xem nhật ký kiểm toán', condition:'' },
  { id:'gt18', subject:['role=bacsi'], object:'hoSoBenhAn/*/ketQuaXetNghiem', actions:['read','write'], permission:'grant', reason:'Bác sĩ cập nhật kết quả xét nghiệm', condition:'' },
  { id:'gt19', subject:['role=yta'], object:'*', actions:['delete'], permission:'deny', reason:'Y tá không được xóa bất kỳ dữ liệu nào', condition:'' },
  { id:'gt20', subject:['role=admin'], object:'nhanVien/*/luong', actions:['read','write'], permission:'grant', reason:'Chỉ admin quản lý thông tin lương', condition:'' }
];

// 30 ca kiểm thử cho dataset bệnh viện (chỉ dùng khi nạp mẫu Bệnh viện)
const HOSPITAL_TESTS = [
  {id:'tc01',subject:['role=admin'],object:'benhNhan',action:'read',ctx:{},expected:true,desc:'Admin đọc bảng bệnh nhân'},
  {id:'tc02',subject:['role=admin'],object:'audit',action:'read',ctx:{},expected:true,desc:'Admin xem nhật ký kiểm toán'},
  {id:'tc03',subject:['role=bacsi'],object:'hoSoBenhAn',action:'read',ctx:{},expected:true,desc:'Bác sĩ đọc hồ sơ bệnh án'},
  {id:'tc04',subject:['role=bacsi'],object:'hoSoBenhAn',action:'write',ctx:{},expected:true,desc:'Bác sĩ ghi hồ sơ bệnh án'},
  {id:'tc05',subject:['role=bacsi'],object:'donthuoc',action:'write',ctx:{},expected:true,desc:'Bác sĩ kê đơn thuốc'},
  {id:'tc06',subject:['role=bacsi'],object:'lichHen',action:'read',ctx:{},expected:true,desc:'Bác sĩ xem lịch hẹn'},
  {id:'tc07',subject:['role=yta'],object:'benhNhan',action:'read',ctx:{},expected:true,desc:'Y tá đọc thông tin bệnh nhân'},
  {id:'tc08',subject:['role=yta'],object:'lichHen',action:'write',ctx:{},expected:true,desc:'Y tá cập nhật lịch hẹn'},
  {id:'tc09',subject:['role=yta'],object:'hoSoBenhAn',action:'read',ctx:{},expected:true,desc:'Y tá đọc hồ sơ bệnh án'},
  {id:'tc10',subject:['role=benhnhan'],object:'benhNhan/bn001/tenHo',action:'read',ctx:{},expected:true,desc:'Bệnh nhân đọc tên của mình'},
  {id:'tc11',subject:['role=benhnhan'],object:'lichHen',action:'read',ctx:{},expected:true,desc:'Bệnh nhân xem lịch hẹn'},
  {id:'tc12',subject:['role=duoc'],object:'donthuoc',action:'read',ctx:{},expected:true,desc:'Dược sĩ xem đơn thuốc'},
  {id:'tc13',subject:['role=duoc'],object:'thuoc',action:'write',ctx:{},expected:true,desc:'Dược sĩ cập nhật kho thuốc'},
  {id:'tc14',subject:['role=bacsi'],object:'hoSoBenhAn/hs001/ketQuaXetNghiem',action:'read',ctx:{},expected:true,desc:'Bác sĩ đọc kết quả xét nghiệm'},
  {id:'tc15',subject:['role=admin'],object:'nhanVien/bs001/luong',action:'read',ctx:{},expected:true,desc:'Admin xem mức lương nhân viên'},
  {id:'tc16',subject:['role=yta'],object:'hoSoBenhAn/hs001/chanDoan',action:'read',ctx:{},expected:false,desc:'Y tá đọc chẩn đoán (phải bị chặn)'},
  {id:'tc17',subject:['role=yta'],object:'hoSoBenhAn/hs001/chanDoan',action:'write',ctx:{},expected:false,desc:'Y tá sửa chẩn đoán (phải bị chặn)'},
  {id:'tc18',subject:['role=benhnhan'],object:'hoSoBenhAn',action:'read',ctx:{},expected:false,desc:'Bệnh nhân đọc hồ sơ bệnh án (phải bị chặn)'},
  {id:'tc19',subject:['role=benhnhan'],object:'hoSoBenhAn',action:'write',ctx:{},expected:false,desc:'Bệnh nhân sửa hồ sơ bệnh án (phải bị chặn)'},
  {id:'tc20',subject:['role=user'],object:'benhNhan/bn001/cccd',action:'read',ctx:{},expected:false,desc:'Người dùng đọc CCCD (phải bị chặn)'},
  {id:'tc21',subject:['role=user'],object:'benhNhan/bn001/sdt',action:'read',ctx:{},expected:false,desc:'Người dùng đọc số điện thoại (phải bị chặn)'},
  {id:'tc22',subject:['role=yta'],object:'benhNhan',action:'delete',ctx:{},expected:false,desc:'Y tá xóa bệnh nhân (phải bị chặn)'},
  {id:'tc23',subject:['role=duoc'],object:'hoSoBenhAn',action:'read',ctx:{},expected:false,desc:'Dược sĩ đọc hồ sơ bệnh án (không có quyền)'},
  {id:'tc24',subject:['role=duoc'],object:'donthuoc',action:'delete',ctx:{},expected:false,desc:'Dược sĩ xóa đơn thuốc (không có quyền)'},
  {id:'tc25',subject:['role=benhnhan'],object:'audit',action:'read',ctx:{},expected:false,desc:'Bệnh nhân xem nhật ký (phải bị chặn)'},
  {id:'tc26',subject:['role=benhnhan'],object:'nhanVien/bs001/luong',action:'read',ctx:{},expected:false,desc:'Bệnh nhân xem lương nhân viên (phải bị chặn)'},
  {id:'tc27',subject:['role=bacsi'],object:'audit',action:'delete',ctx:{},expected:false,desc:'Bác sĩ xóa nhật ký (không có quyền)'},
  {id:'tc28',subject:['role=duoc'],object:'benhNhan',action:'write',ctx:{},expected:false,desc:'Dược sĩ sửa thông tin bệnh nhân (không có quyền)'},
  {id:'tc29',subject:['role=user'],object:'nhanVien/bs001/bangCap',action:'read',ctx:{},expected:false,desc:'Người dùng đọc bằng cấp nhân viên (không có quyền)'},
  {id:'tc30',subject:['role=benhnhan'],object:'thuoc',action:'write',ctx:{},expected:false,desc:'Bệnh nhân sửa kho thuốc (không có quyền)'}
];

module.exports = { HOSPITAL_DATA, HOSPITAL_GT, HOSPITAL_TESTS };
