// Dataset Olist Brazilian E-Commerce (Kaggle: olistbr/brazilian-ecommerce): dữ liệu + 15 luật chuẩn + 30 ca kiểm thử (benchmark)
// Tên bảng và tên cột giữ nguyên theo bộ dữ liệu Olist (kể cả lỗi chính tả gốc "lenght"). Mỗi bảng chỉ lấy vài dòng mẫu liên kết với nhau;
// muốn dùng dữ liệu đầy đủ, tải CSV từ Kaggle rồi nạp ở "Nạp dữ liệu → Tải file".
const OLIST_DATA = {
  customers: [
    { customer_id: 'a9f7e97965d6cf799a529102a973b8b9', customer_unique_id: 'e4774cdda0793f86414e8b9140bb6db4', customer_zip_code_prefix: '14409', customer_city: 'franca', customer_state: 'SP' },
    { customer_id: '9ab62b5ef34a985438bfdf7ee0102229', customer_unique_id: '270c1b084f3f146eb5787075158d9c53', customer_zip_code_prefix: '09790', customer_city: 'sao bernardo do campo', customer_state: 'SP' },
    { customer_id: '0a3d72134fb3d6c024db4c510bc1605b', customer_unique_id: '532a7b8e0328a8d05a8e6258b28b9a36', customer_zip_code_prefix: '01151', customer_city: 'sao paulo', customer_state: 'SP' }
  ],
  orders: [
    { order_id: 'f1584b995a4770986ad75bb8d29e9734', customer_id: 'a9f7e97965d6cf799a529102a973b8b9', order_status: 'delivered', order_purchase_timestamp: '2017-10-02 10:56:33', order_approved_at: '2017-10-02 11:07:15', order_delivered_carrier_date: '2017-10-04 19:55:00', order_delivered_customer_date: '2017-10-10 21:25:13', order_estimated_delivery_date: '2017-10-18 00:00:00' },
    { order_id: '2d387ab98437e5f528a87b031a086256', customer_id: '9ab62b5ef34a985438bfdf7ee0102229', order_status: 'delivered', order_purchase_timestamp: '2018-07-24 20:41:37', order_approved_at: '2018-07-26 03:24:27', order_delivered_carrier_date: '2018-07-26 14:31:00', order_delivered_customer_date: '2018-08-07 15:27:45', order_estimated_delivery_date: '2018-08-13 00:00:00' },
    { order_id: '417c4fa3b4135a6c64e05f8d35f71648', customer_id: '0a3d72134fb3d6c024db4c510bc1605b', order_status: 'shipped', order_purchase_timestamp: '2018-08-08 08:38:49', order_approved_at: '2018-08-08 08:55:23', order_delivered_carrier_date: '2018-08-08 13:50:00', order_delivered_customer_date: '', order_estimated_delivery_date: '2018-09-04 00:00:00' }
  ],
  order_items: [
    { order_id: 'f1584b995a4770986ad75bb8d29e9734', order_item_id: 1, product_id: 'ec6ef230f1828039ee794566b9c58adc', seller_id: '8ddf878039b70767c4a5bcf4f0c4f65e', shipping_limit_date: '2017-10-06 11:07:15', price: 29.99, freight_value: 8.72 },
    { order_id: '2d387ab98437e5f528a87b031a086256', order_item_id: 1, product_id: '1d665b9b1467944c128a5575119d1cfd', seller_id: 'fac989447cad2edbc89fbcba70003b36', shipping_limit_date: '2018-07-30 03:24:27', price: 118.7, freight_value: 22.76 },
    { order_id: '417c4fa3b4135a6c64e05f8d35f71648', order_item_id: 1, product_id: '7bc3ca68769437ce986455407dab2a1f', seller_id: 'c0828e0381730befd1f7a025057c74fb', shipping_limit_date: '2018-08-13 08:55:23', price: 159.9, freight_value: 19.22 }
  ],
  order_payments: [
    { order_id: 'f1584b995a4770986ad75bb8d29e9734', payment_sequential: 1, payment_type: 'credit_card', payment_installments: 1, payment_value: 38.71 },
    { order_id: '2d387ab98437e5f528a87b031a086256', payment_sequential: 1, payment_type: 'boleto', payment_installments: 1, payment_value: 141.46 },
    { order_id: '417c4fa3b4135a6c64e05f8d35f71648', payment_sequential: 1, payment_type: 'credit_card', payment_installments: 3, payment_value: 179.12 }
  ],
  order_reviews: [
    { review_id: '7c92cf1eee8d99cc85f8355a3d6e4b86', order_id: 'f1584b995a4770986ad75bb8d29e9734', review_score: 4, review_comment_title: '', review_comment_message: '', review_creation_date: '2017-10-11 00:00:00', review_answer_timestamp: '2017-10-12 03:43:48' },
    { review_id: 'd279186428a75016b17e4df5ea43d080', order_id: '2d387ab98437e5f528a87b031a086256', review_score: 5, review_comment_title: '', review_comment_message: 'Recebi bem antes do prazo estipulado.', review_creation_date: '2018-08-08 00:00:00', review_answer_timestamp: '2018-08-08 18:37:50' },
    { review_id: '9d3e622df914d8de7f747b7b8b143c52', order_id: '417c4fa3b4135a6c64e05f8d35f71648', review_score: 1, review_comment_title: 'Atraso', review_comment_message: 'Produto ainda nao chegou.', review_creation_date: '2018-09-05 00:00:00', review_answer_timestamp: '2018-09-06 10:12:04' }
  ],
  products: [
    { product_id: 'ec6ef230f1828039ee794566b9c58adc', product_category_name: 'perfumaria', product_name_lenght: 40, product_description_lenght: 287, product_photos_qty: 1, product_weight_g: 225, product_length_cm: 16, product_height_cm: 10, product_width_cm: 14 },
    { product_id: '1d665b9b1467944c128a5575119d1cfd', product_category_name: 'utilidades_domesticas', product_name_lenght: 55, product_description_lenght: 411, product_photos_qty: 3, product_weight_g: 1800, product_length_cm: 35, product_height_cm: 20, product_width_cm: 25 },
    { product_id: '7bc3ca68769437ce986455407dab2a1f', product_category_name: 'informatica_acessorios', product_name_lenght: 48, product_description_lenght: 602, product_photos_qty: 4, product_weight_g: 650, product_length_cm: 28, product_height_cm: 9, product_width_cm: 22 }
  ],
  sellers: [
    { seller_id: '8ddf878039b70767c4a5bcf4f0c4f65e', seller_zip_code_prefix: '13023', seller_city: 'campinas', seller_state: 'SP' },
    { seller_id: 'fac989447cad2edbc89fbcba70003b36', seller_zip_code_prefix: '20031', seller_city: 'rio de janeiro', seller_state: 'RJ' },
    { seller_id: 'c0828e0381730befd1f7a025057c74fb', seller_zip_code_prefix: '80250', seller_city: 'curitiba', seller_state: 'PR' }
  ]
};

// 15 luật chuẩn (ground truth). Tên vai trò, đường dẫn đối tượng (có "/*") và điều kiện phải giống hệt luật AI thì mới tính là khớp khi so sánh.
const OLIST_GT = [
  { id:'gt01', subject:['role=admin'], object:'*', actions:['*'], permission:'grant', reason:'Quản trị viên hệ thống có toàn quyền quản lý kỹ thuật và cấu hình tổng thể.', condition:'' },
  { id:'gt02', subject:['role=admin'], object:'customers/*/customer_unique_id', actions:['read'], permission:'deny', reason:'Quản trị viên kỹ thuật không được xem mã định danh khách hàng (dữ liệu cá nhân, LGPD/NIST IR 8504).', condition:'' },
  { id:'gt03', subject:['role=seller'], object:'order_items/*', actions:['read'], permission:'grant', reason:'Người bán chỉ xem các dòng hàng thuộc về chính mình.', condition:'user.id == resource.seller_id' },
  { id:'gt04', subject:['role=seller'], object:'products/*', actions:['read'], permission:'grant', reason:'Người bán xem danh mục sản phẩm để quản lý gian hàng.', condition:'' },
  { id:'gt05', subject:['role=seller'], object:'sellers/*', actions:['read', 'write'], permission:'grant', reason:'Người bán xem và cập nhật hồ sơ của chính mình.', condition:'user.id == resource.seller_id' },
  { id:'gt06', subject:['role=seller'], object:'customers/*', actions:['read'], permission:'deny', reason:'Người bán không được xem thông tin cá nhân của khách hàng.', condition:'' },
  { id:'gt07', subject:['role=customer'], object:'orders/*', actions:['read'], permission:'grant', reason:'Khách hàng chỉ xem đơn hàng của chính mình.', condition:'user.id == resource.customer_id' },
  { id:'gt08', subject:['role=customer'], object:'customers/*', actions:['read', 'write'], permission:'grant', reason:'Khách hàng xem và cập nhật hồ sơ cá nhân của mình.', condition:'user.id == resource.customer_id' },
  { id:'gt09', subject:['role=customer'], object:'order_reviews/*', actions:['read', 'write'], permission:'grant', reason:'Khách hàng xem và viết đánh giá cho đơn hàng của mình.', condition:'user.orderId == resource.order_id' },
  { id:'gt10', subject:['role=support'], object:'orders/*', actions:['read'], permission:'grant', reason:'Nhân viên chăm sóc khách hàng xem đơn hàng để xử lý khiếu nại.', condition:'' },
  { id:'gt11', subject:['role=support'], object:'order_reviews/*', actions:['read', 'write'], permission:'grant', reason:'Nhân viên chăm sóc khách hàng đọc và phản hồi đánh giá.', condition:'' },
  { id:'gt12', subject:['role=support'], object:'customers/*', actions:['read'], permission:'grant', reason:'Nhân viên chăm sóc khách hàng xem hồ sơ khách để liên hệ hỗ trợ.', condition:'' },
  { id:'gt13', subject:['role=finance'], object:'order_payments/*', actions:['read'], permission:'grant', reason:'Kế toán đối soát thanh toán của đơn hàng.', condition:'' },
  { id:'gt14', subject:['role=analyst'], object:'orders/*', actions:['read'], permission:'grant', reason:'Chuyên viên phân tích đọc dữ liệu đơn hàng để làm báo cáo.', condition:'' },
  { id:'gt15', subject:['role=*'], object:'orders/*', actions:['delete'], permission:'deny', reason:'Không ai được xóa đơn hàng để phục vụ đối soát và lưu vết.', condition:'' }
];

// 30 ca kiểm thử cho 15 luật trên (chỉ dùng khi nạp mẫu Olist)
// - object dùng đường dẫn cụ thể (vd orders/o1) vì luật có dạng "orders/*"
// - ctx cung cấp giá trị cho các điều kiện (user.* / resource.*)
const OLIST_TESTS = [
  {id:'tc01',subject:['role=admin'],object:'orders/o1',action:'read',ctx:{},expected:true,desc:'Admin đọc đơn hàng'},
  {id:'tc02',subject:['role=admin'],object:'products/p1',action:'delete',ctx:{},expected:true,desc:'Admin xóa sản phẩm (toàn quyền)'},
  {id:'tc03',subject:['role=admin'],object:'customers/c1/customer_unique_id',action:'read',ctx:{},expected:false,desc:'Admin đọc mã định danh khách hàng (phải bị chặn)'},
  {id:'tc04',subject:['role=admin'],object:'customers/c1/customer_unique_id',action:'write',ctx:{},expected:true,desc:'Admin ghi mã định danh (deny chỉ áp dụng cho read)'},
  {id:'tc05',subject:['role=admin'],object:'customers/c1/customer_city',action:'read',ctx:{},expected:true,desc:'Admin đọc thành phố khách hàng (không thuộc luật chặn)'},
  {id:'tc06',subject:['role=seller'],object:'order_items/i1',action:'read',ctx:{'user.id': 's1', 'resource.seller_id': 's1'},expected:true,desc:'Người bán đọc dòng hàng của mình'},
  {id:'tc07',subject:['role=seller'],object:'order_items/i2',action:'read',ctx:{'user.id': 's1', 'resource.seller_id': 's2'},expected:false,desc:'Người bán đọc dòng hàng của người bán khác (phải bị chặn)'},
  {id:'tc08',subject:['role=seller'],object:'order_items/i1',action:'write',ctx:{'user.id': 's1', 'resource.seller_id': 's1'},expected:false,desc:'Người bán sửa dòng hàng (không có quyền)'},
  {id:'tc09',subject:['role=seller'],object:'products/p1',action:'read',ctx:{},expected:true,desc:'Người bán xem sản phẩm'},
  {id:'tc10',subject:['role=seller'],object:'products/p1',action:'write',ctx:{},expected:false,desc:'Người bán sửa sản phẩm (không có quyền)'},
  {id:'tc11',subject:['role=seller'],object:'sellers/s1',action:'write',ctx:{'user.id': 's1', 'resource.seller_id': 's1'},expected:true,desc:'Người bán sửa hồ sơ của mình'},
  {id:'tc12',subject:['role=seller'],object:'sellers/s2',action:'write',ctx:{'user.id': 's1', 'resource.seller_id': 's2'},expected:false,desc:'Người bán sửa hồ sơ người bán khác (phải bị chặn)'},
  {id:'tc13',subject:['role=seller'],object:'customers/c1',action:'read',ctx:{},expected:false,desc:'Người bán đọc thông tin khách hàng (phải bị chặn)'},
  {id:'tc14',subject:['role=customer'],object:'orders/o1',action:'read',ctx:{'user.id': 'c1', 'resource.customer_id': 'c1'},expected:true,desc:'Khách hàng đọc đơn hàng của mình'},
  {id:'tc15',subject:['role=customer'],object:'orders/o2',action:'read',ctx:{'user.id': 'c1', 'resource.customer_id': 'c2'},expected:false,desc:'Khách hàng đọc đơn hàng của người khác (phải bị chặn)'},
  {id:'tc16',subject:['role=customer'],object:'orders/o1',action:'write',ctx:{'user.id': 'c1', 'resource.customer_id': 'c1'},expected:false,desc:'Khách hàng sửa đơn hàng (không có quyền)'},
  {id:'tc17',subject:['role=customer'],object:'customers/c1',action:'write',ctx:{'user.id': 'c1', 'resource.customer_id': 'c1'},expected:true,desc:'Khách hàng cập nhật hồ sơ của mình'},
  {id:'tc18',subject:['role=customer'],object:'customers/c2',action:'read',ctx:{'user.id': 'c1', 'resource.customer_id': 'c2'},expected:false,desc:'Khách hàng đọc hồ sơ người khác (phải bị chặn)'},
  {id:'tc19',subject:['role=customer'],object:'order_reviews/r1',action:'write',ctx:{'user.orderId': 'o1', 'resource.order_id': 'o1'},expected:true,desc:'Khách hàng viết đánh giá cho đơn của mình'},
  {id:'tc20',subject:['role=customer'],object:'order_reviews/r2',action:'read',ctx:{'user.orderId': 'o1', 'resource.order_id': 'o2'},expected:false,desc:'Khách hàng đọc đánh giá đơn của người khác (phải bị chặn)'},
  {id:'tc21',subject:['role=support'],object:'orders/o1',action:'read',ctx:{},expected:true,desc:'CSKH xem đơn hàng'},
  {id:'tc22',subject:['role=support'],object:'order_reviews/r1',action:'write',ctx:{},expected:true,desc:'CSKH phản hồi đánh giá'},
  {id:'tc23',subject:['role=support'],object:'customers/c1',action:'read',ctx:{},expected:true,desc:'CSKH xem hồ sơ khách hàng'},
  {id:'tc24',subject:['role=support'],object:'order_payments/o1',action:'read',ctx:{},expected:false,desc:'CSKH đọc thanh toán (không có quyền)'},
  {id:'tc25',subject:['role=finance'],object:'order_payments/o1',action:'read',ctx:{},expected:true,desc:'Kế toán đọc thanh toán'},
  {id:'tc26',subject:['role=finance'],object:'order_payments/o1',action:'write',ctx:{},expected:false,desc:'Kế toán sửa thanh toán (không có quyền)'},
  {id:'tc27',subject:['role=analyst'],object:'orders/o1',action:'read',ctx:{},expected:true,desc:'Chuyên viên phân tích đọc đơn hàng'},
  {id:'tc28',subject:['role=analyst'],object:'customers/c1/customer_unique_id',action:'read',ctx:{},expected:false,desc:'Chuyên viên phân tích đọc mã khách hàng (không có quyền)'},
  {id:'tc29',subject:['role=support', 'role=*'],object:'orders/o1',action:'delete',ctx:{},expected:false,desc:'CSKH xóa đơn hàng (phải bị chặn)'},
  {id:'tc30',subject:['role=admin', 'role=*'],object:'orders/o1',action:'delete',ctx:{},expected:false,desc:'Admin xóa đơn hàng (deny thắng grant toàn quyền)'}
];

module.exports = { OLIST_DATA, OLIST_GT, OLIST_TESTS };
