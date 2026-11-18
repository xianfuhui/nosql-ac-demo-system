// Dataset Bệnh viện Đa khoa: dữ liệu + 15 luật chuẩn + 30 ca kiểm thử (benchmark)
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

// 15 luật chuẩn (ground truth) - khớp với bộ luật AI đã sinh & được duyệt cho dataset bệnh viện
// Lưu ý: tên vai trò, đường dẫn đối tượng (có "/*") và điều kiện phải giống hệt luật AI thì mới tính là khớp khi so sánh.
const HOSPITAL_GT = [
  { id:'gt01', subject:['role=admin'], object:'*', actions:['*'], permission:'grant', reason:'Quản trị viên hệ thống có toàn quyền quản lý kỹ thuật và cấu hình tổng thể theo tiêu chuẩn kiểm soát truy cập.', condition:'' },
  { id:'gt02', subject:['role=admin'], object:'hoSoBenhAn/*/ketQuaXetNghiem', actions:['read'], permission:'deny', reason:'Tuân thủ nguyên tắc quyền riêng tư NIST IR 8504, quản trị viên không được phép xem chi tiết kết quả y tế nhạy cảm của bệnh nhân.', condition:'' },
  { id:'gt03', subject:['role=bacSi'], object:'hoSoBenhAn/*', actions:['read','write'], permission:'grant', reason:'Bác sĩ được phép xem và chẩn đoán, cập nhật hồ sơ bệnh án thuộc khoa chuyên môn của mình.', condition:'user.khoa == resource.khoa' },
  { id:'gt04', subject:['role=bacSi'], object:'donthuoc/*', actions:['read','write'], permission:'grant', reason:'Bác sĩ có quyền kê đơn thuốc và chỉnh sửa đơn thuốc do chính mình tạo ra.', condition:'user.id == resource.bacSiKe' },
  { id:'gt05', subject:['role=bacSi'], object:'benhNhan/*', actions:['read'], permission:'grant', reason:'Bác sĩ cần truy cập thông tin hành chính và nhóm máu của bệnh nhân để phục vụ công tác khám chữa bệnh.', condition:'' },
  { id:'gt06', subject:['role=duocSi'], object:'donthuoc/*', actions:['read'], permission:'grant', reason:'Dược sĩ có quyền xem thông tin đơn thuốc để thực hiện cấp phát thuốc cho bệnh nhân.', condition:'' },
  { id:'gt07', subject:['role=duocSi'], object:'thuoc/*', actions:['read','write'], permission:'grant', reason:'Dược sĩ quản lý kho thuốc, có quyền cập nhật giá, số lượng tồn kho và hạn sử dụng của thuốc.', condition:'' },
  { id:'gt08', subject:['role=benhNhan'], object:'benhNhan/*', actions:['read'], permission:'grant', reason:'Bệnh nhân chỉ có quyền xem thông tin cá nhân của chính mình.', condition:'user.id == resource._id' },
  { id:'gt09', subject:['role=benhNhan'], object:'hoSoBenhAn/*', actions:['read'], permission:'grant', reason:'Bệnh nhân có quyền truy cập xem lịch sử khám và hồ sơ bệnh án cá nhân.', condition:'user.id == resource.benhNhanId' },
  { id:'gt10', subject:['role=benhNhan'], object:'lichHen/*', actions:['read','write'], permission:'grant', reason:'Bệnh nhân có quyền đặt, xem và hủy lịch hẹn khám của cá nhân mình.', condition:'user.id == resource.benhNhanId' },
  { id:'gt11', subject:['role=nhanVienLieuLienLienLac'], object:'lichHen/*', actions:['read','write'], permission:'grant', reason:'Nhân viên tiếp tân/tiếp nhận có quyền quản lý, điều phối lịch hẹn khám bệnh của toàn hệ thống.', condition:'' },
  { id:'gt12', subject:['role=nhanVienLieuLienLienLac'], object:'benhNhan/*', actions:['read','write'], permission:'grant', reason:'Nhân viên tiếp tân có quyền tiếp nhận và cập nhật thông tin hành chính của bệnh nhân mới.', condition:'' },
  { id:'gt13', subject:['role=nhanVien'], object:'nhanVien/*/luong', actions:['read'], permission:'deny', reason:'Đảm bảo tính bảo mật tiền lương, nhân viên không thể xem lương của đồng nghiệp.', condition:'user.id != resource._id' },
  { id:'gt14', subject:['role=quanLyNhanSu'], object:'nhanVien/*', actions:['read','write'], permission:'grant', reason:'Quản lý nhân sự có quyền truy cập và cập nhật hồ sơ, lương và bằng cấp của nhân viên.', condition:'' },
  { id:'gt15', subject:['role=*'], object:'hoSoBenhAn/*', actions:['delete'], permission:'deny', reason:'Ngăn chặn việc xóa hồ sơ bệnh án tuân thủ quy định lưu trữ dữ liệu y tế quốc gia.', condition:'' }
];

// 30 ca kiểm thử cho 15 luật trên (chỉ dùng khi nạp mẫu Bệnh viện)
// - object dùng đường dẫn cụ thể (vd hoSoBenhAn/hs001) vì luật có dạng "hoSoBenhAn/*"
// - ctx cung cấp giá trị cho các điều kiện (user.* / resource.*)
const K_OK  = { 'user.khoa':'Nội khoa', 'resource.khoa':'Nội khoa' };
const K_BAD = { 'user.khoa':'Nội khoa', 'resource.khoa':'Hô hấp' };
const HOSPITAL_TESTS = [
  // admin (gt01, gt02)
  {id:'tc01',subject:['role=admin'],object:'benhNhan/bn001',action:'read',ctx:{},expected:true,desc:'Admin đọc thông tin bệnh nhân'},
  {id:'tc02',subject:['role=admin'],object:'thuoc/th001',action:'delete',ctx:{},expected:true,desc:'Admin xóa thuốc (toàn quyền)'},
  {id:'tc03',subject:['role=admin'],object:'hoSoBenhAn/hs001/ketQuaXetNghiem',action:'read',ctx:{},expected:false,desc:'Admin đọc kết quả xét nghiệm (phải bị chặn)'},
  {id:'tc04',subject:['role=admin'],object:'hoSoBenhAn/hs001/ketQuaXetNghiem',action:'write',ctx:{},expected:true,desc:'Admin ghi kết quả xét nghiệm (deny chỉ áp dụng cho read)'},
  {id:'tc05',subject:['role=admin'],object:'hoSoBenhAn/hs001/chanDoan',action:'read',ctx:{},expected:true,desc:'Admin đọc chẩn đoán (không thuộc luật chặn)'},
  // bác sĩ (gt03, gt04, gt05)
  {id:'tc06',subject:['role=bacSi'],object:'hoSoBenhAn/hs001',action:'read',ctx:K_OK,expected:true,desc:'Bác sĩ đọc hồ sơ cùng khoa'},
  {id:'tc07',subject:['role=bacSi'],object:'hoSoBenhAn/hs001',action:'write',ctx:K_OK,expected:true,desc:'Bác sĩ ghi hồ sơ cùng khoa'},
  {id:'tc08',subject:['role=bacSi'],object:'hoSoBenhAn/hs002',action:'read',ctx:K_BAD,expected:false,desc:'Bác sĩ đọc hồ sơ khác khoa (phải bị chặn)'},
  {id:'tc09',subject:['role=bacSi'],object:'donthuoc/dt001',action:'write',ctx:{'user.id':'bs001','resource.bacSiKe':'bs001'},expected:true,desc:'Bác sĩ sửa đơn thuốc do mình kê'},
  {id:'tc10',subject:['role=bacSi'],object:'donthuoc/dt002',action:'write',ctx:{'user.id':'bs001','resource.bacSiKe':'bs002'},expected:false,desc:'Bác sĩ sửa đơn thuốc của bác sĩ khác (phải bị chặn)'},
  {id:'tc11',subject:['role=bacSi'],object:'benhNhan/bn001',action:'read',ctx:{},expected:true,desc:'Bác sĩ xem thông tin bệnh nhân'},
  {id:'tc12',subject:['role=bacSi'],object:'benhNhan/bn001',action:'write',ctx:{},expected:false,desc:'Bác sĩ sửa thông tin hành chính bệnh nhân (không có quyền)'},
  // dược sĩ (gt06, gt07)
  {id:'tc13',subject:['role=duocSi'],object:'donthuoc/dt001',action:'read',ctx:{},expected:true,desc:'Dược sĩ xem đơn thuốc'},
  {id:'tc14',subject:['role=duocSi'],object:'donthuoc/dt001',action:'write',ctx:{},expected:false,desc:'Dược sĩ sửa đơn thuốc (không có quyền)'},
  {id:'tc15',subject:['role=duocSi'],object:'thuoc/th001',action:'write',ctx:{},expected:true,desc:'Dược sĩ cập nhật kho thuốc'},
  {id:'tc16',subject:['role=duocSi'],object:'hoSoBenhAn/hs001',action:'read',ctx:{},expected:false,desc:'Dược sĩ đọc hồ sơ bệnh án (không có quyền)'},
  // bệnh nhân (gt08, gt09, gt10)
  {id:'tc17',subject:['role=benhNhan'],object:'benhNhan/bn001',action:'read',ctx:{'user.id':'bn001','resource._id':'bn001'},expected:true,desc:'Bệnh nhân đọc thông tin của chính mình'},
  {id:'tc18',subject:['role=benhNhan'],object:'benhNhan/bn002',action:'read',ctx:{'user.id':'bn001','resource._id':'bn002'},expected:false,desc:'Bệnh nhân đọc thông tin người khác (phải bị chặn)'},
  {id:'tc19',subject:['role=benhNhan'],object:'hoSoBenhAn/hs001',action:'read',ctx:{'user.id':'bn001','resource.benhNhanId':'bn001'},expected:true,desc:'Bệnh nhân đọc hồ sơ bệnh án của mình'},
  {id:'tc20',subject:['role=benhNhan'],object:'hoSoBenhAn/hs001',action:'write',ctx:{'user.id':'bn001','resource.benhNhanId':'bn001'},expected:false,desc:'Bệnh nhân sửa hồ sơ bệnh án (phải bị chặn)'},
  {id:'tc21',subject:['role=benhNhan'],object:'lichHen/lh001',action:'write',ctx:{'user.id':'bn001','resource.benhNhanId':'bn001'},expected:true,desc:'Bệnh nhân đặt/hủy lịch hẹn của mình'},
  {id:'tc22',subject:['role=benhNhan'],object:'lichHen/lh002',action:'read',ctx:{'user.id':'bn001','resource.benhNhanId':'bn003'},expected:false,desc:'Bệnh nhân xem lịch hẹn của người khác (phải bị chặn)'},
  // nhân viên tiếp nhận (gt11, gt12)
  {id:'tc23',subject:['role=nhanVienLieuLienLienLac'],object:'lichHen/lh001',action:'write',ctx:{},expected:true,desc:'Nhân viên tiếp nhận điều phối lịch hẹn'},
  {id:'tc24',subject:['role=nhanVienLieuLienLienLac'],object:'benhNhan/bn001',action:'write',ctx:{},expected:true,desc:'Nhân viên tiếp nhận cập nhật thông tin hành chính bệnh nhân'},
  {id:'tc25',subject:['role=nhanVienLieuLienLienLac'],object:'hoSoBenhAn/hs001',action:'read',ctx:{},expected:false,desc:'Nhân viên tiếp nhận đọc hồ sơ bệnh án (không có quyền)'},
  // nhân viên / quản lý nhân sự (gt13, gt14)
  {id:'tc26',subject:['role=nhanVien'],object:'nhanVien/bs002/luong',action:'read',ctx:{'user.id':'bs001','resource._id':'bs002'},expected:false,desc:'Nhân viên xem lương đồng nghiệp (phải bị chặn)'},
  {id:'tc27',subject:['role=quanLyNhanSu'],object:'nhanVien/bs001/luong',action:'write',ctx:{},expected:true,desc:'Quản lý nhân sự cập nhật lương nhân viên'},
  {id:'tc28',subject:['role=quanLyNhanSu'],object:'thuoc/th001',action:'read',ctx:{},expected:false,desc:'Quản lý nhân sự đọc kho thuốc (không có quyền)'},
  // cấm xóa hồ sơ bệnh án với mọi vai trò (gt15, role=*)
  {id:'tc29',subject:['role=bacSi','role=*'],object:'hoSoBenhAn/hs001',action:'delete',ctx:K_OK,expected:false,desc:'Bác sĩ xóa hồ sơ bệnh án (phải bị chặn)'},
  {id:'tc30',subject:['role=admin','role=*'],object:'hoSoBenhAn/hs001',action:'delete',ctx:{},expected:false,desc:'Admin xóa hồ sơ bệnh án (deny thắng grant toàn quyền)'}
];

module.exports = { HOSPITAL_DATA, HOSPITAL_GT, HOSPITAL_TESTS };
