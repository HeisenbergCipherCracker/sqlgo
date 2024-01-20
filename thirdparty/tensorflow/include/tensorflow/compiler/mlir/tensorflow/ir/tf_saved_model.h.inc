/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Op Declarations                                                            *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|* From: tf_saved_model_ops.td                                                *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#if defined(GET_OP_CLASSES) || defined(GET_OP_FWD_DEFINES)
#undef GET_OP_FWD_DEFINES
namespace mlir {
namespace tf_saved_model {
class AssetOp;
} // namespace tf_saved_model
} // namespace mlir
namespace mlir {
namespace tf_saved_model {
class GlobalTensorOp;
} // namespace tf_saved_model
} // namespace mlir
namespace mlir {
namespace tf_saved_model {
class SessionInitializerOp;
} // namespace tf_saved_model
} // namespace mlir
#endif

#ifdef GET_OP_CLASSES
#undef GET_OP_CLASSES


//===----------------------------------------------------------------------===//
// Local Utility Method Definitions
//===----------------------------------------------------------------------===//

namespace mlir {
namespace tf_saved_model {

//===----------------------------------------------------------------------===//
// ::mlir::tf_saved_model::AssetOp declarations
//===----------------------------------------------------------------------===//

namespace detail {
class AssetOpGenericAdaptorBase {
public:
protected:
  ::mlir::DictionaryAttr odsAttrs;
  ::std::optional<::mlir::OperationName> odsOpName;
  ::mlir::RegionRange odsRegions;
public:
  AssetOpGenericAdaptorBase(::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {});

  AssetOpGenericAdaptorBase(AssetOp op);

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index, unsigned odsOperandsSize);
  ::mlir::DictionaryAttr getAttributes();
  ::mlir::StringAttr getSymNameAttr();
  ::llvm::StringRef getSymName();
  ::mlir::StringAttr getFilenameAttr();
  ::llvm::StringRef getFilename();
};
} // namespace detail
template <typename RangeT>
class AssetOpGenericAdaptor : public detail::AssetOpGenericAdaptorBase {
  using ValueT = ::llvm::detail::ValueOfRange<RangeT>;
  using Base = detail::AssetOpGenericAdaptorBase;
public:
  AssetOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {}) : Base(attrs, properties, regions), odsOperands(values) {}

  AssetOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs, ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions = {}) : AssetOpGenericAdaptor(values, attrs, (properties ? *properties.as<::mlir::EmptyProperties *>() : ::mlir::EmptyProperties{}), regions) {}

  template <typename LateInst = AssetOp, typename = std::enable_if_t<std::is_same_v<LateInst, AssetOp>>>
  AssetOpGenericAdaptor(RangeT values, LateInst op) : Base(op), odsOperands(values) {}

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index) {
    return Base::getODSOperandIndexAndLength(index, odsOperands.size());
  }

  RangeT getODSOperands(unsigned index) {
    auto valueRange = getODSOperandIndexAndLength(index);
    return {std::next(odsOperands.begin(), valueRange.first),
             std::next(odsOperands.begin(), valueRange.first + valueRange.second)};
  }

  RangeT getOperands() {
    return odsOperands;
  }

private:
  RangeT odsOperands;
};
class AssetOpAdaptor : public AssetOpGenericAdaptor<::mlir::ValueRange> {
public:
  using AssetOpGenericAdaptor::AssetOpGenericAdaptor;
  AssetOpAdaptor(AssetOp op);

  ::mlir::LogicalResult verify(::mlir::Location loc);
};
class AssetOp : public ::mlir::Op<AssetOp, ::mlir::OpTrait::ZeroRegions, ::mlir::OpTrait::ZeroResults, ::mlir::OpTrait::ZeroSuccessors, ::mlir::OpTrait::ZeroOperands, ::mlir::OpTrait::OpInvariants, ::mlir::SymbolOpInterface::Trait> {
public:
  using Op::Op;
  using Op::print;
  using Adaptor = AssetOpAdaptor;
  template <typename RangeT>
  using GenericAdaptor = AssetOpGenericAdaptor<RangeT>;
  using FoldAdaptor = GenericAdaptor<::llvm::ArrayRef<::mlir::Attribute>>;
  static ::llvm::ArrayRef<::llvm::StringRef> getAttributeNames() {
    static ::llvm::StringRef attrNames[] = {::llvm::StringRef("filename"), ::llvm::StringRef("sym_name")};
    return ::llvm::ArrayRef(attrNames);
  }

  ::mlir::StringAttr getFilenameAttrName() {
    return getAttributeNameForIndex(0);
  }

  static ::mlir::StringAttr getFilenameAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 0);
  }

  ::mlir::StringAttr getSymNameAttrName() {
    return getAttributeNameForIndex(1);
  }

  static ::mlir::StringAttr getSymNameAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 1);
  }

  static constexpr ::llvm::StringLiteral getOperationName() {
    return ::llvm::StringLiteral("tf_saved_model.asset");
  }

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index);
  ::mlir::Operation::operand_range getODSOperands(unsigned index);
  std::pair<unsigned, unsigned> getODSResultIndexAndLength(unsigned index);
  ::mlir::Operation::result_range getODSResults(unsigned index);
  ::mlir::StringAttr getSymNameAttr();
  ::llvm::StringRef getSymName();
  ::mlir::StringAttr getFilenameAttr();
  ::llvm::StringRef getFilename();
  void setSymNameAttr(::mlir::StringAttr attr);
  void setSymName(::llvm::StringRef attrValue);
  void setFilenameAttr(::mlir::StringAttr attr);
  void setFilename(::llvm::StringRef attrValue);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::StringAttr sym_name, ::mlir::StringAttr filename);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::StringAttr sym_name, ::mlir::StringAttr filename);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::llvm::StringRef sym_name, ::llvm::StringRef filename);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::llvm::StringRef sym_name, ::llvm::StringRef filename);
  static void build(::mlir::OpBuilder &, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::ValueRange operands, ::llvm::ArrayRef<::mlir::NamedAttribute> attributes = {});
  ::mlir::LogicalResult verifyInvariantsImpl();
  ::mlir::LogicalResult verifyInvariants();
private:
  ::mlir::StringAttr getAttributeNameForIndex(unsigned index) {
    return getAttributeNameForIndex((*this)->getName(), index);
  }

  static ::mlir::StringAttr getAttributeNameForIndex(::mlir::OperationName name, unsigned index) {
    assert(index < 2 && "invalid attribute index");
    assert(name.getStringRef() == getOperationName() && "invalid operation name");
    return name.getAttributeNames()[index];
  }

public:
};
} // namespace tf_saved_model
} // namespace mlir
MLIR_DECLARE_EXPLICIT_TYPE_ID(::mlir::tf_saved_model::AssetOp)

namespace mlir {
namespace tf_saved_model {

//===----------------------------------------------------------------------===//
// ::mlir::tf_saved_model::GlobalTensorOp declarations
//===----------------------------------------------------------------------===//

namespace detail {
class GlobalTensorOpGenericAdaptorBase {
public:
protected:
  ::mlir::DictionaryAttr odsAttrs;
  ::std::optional<::mlir::OperationName> odsOpName;
  ::mlir::RegionRange odsRegions;
public:
  GlobalTensorOpGenericAdaptorBase(::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {});

  GlobalTensorOpGenericAdaptorBase(GlobalTensorOp op);

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index, unsigned odsOperandsSize);
  ::mlir::DictionaryAttr getAttributes();
  ::mlir::StringAttr getSymNameAttr();
  ::llvm::StringRef getSymName();
  ::mlir::ElementsAttr getValueAttr();
  ::std::optional< ::mlir::ElementsAttr > getValue();
  ::mlir::TypeAttr getTypeAttr();
  ::mlir::Type getType();
  ::mlir::UnitAttr getIsMutableAttr();
  bool getIsMutable();
};
} // namespace detail
template <typename RangeT>
class GlobalTensorOpGenericAdaptor : public detail::GlobalTensorOpGenericAdaptorBase {
  using ValueT = ::llvm::detail::ValueOfRange<RangeT>;
  using Base = detail::GlobalTensorOpGenericAdaptorBase;
public:
  GlobalTensorOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {}) : Base(attrs, properties, regions), odsOperands(values) {}

  GlobalTensorOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs, ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions = {}) : GlobalTensorOpGenericAdaptor(values, attrs, (properties ? *properties.as<::mlir::EmptyProperties *>() : ::mlir::EmptyProperties{}), regions) {}

  template <typename LateInst = GlobalTensorOp, typename = std::enable_if_t<std::is_same_v<LateInst, GlobalTensorOp>>>
  GlobalTensorOpGenericAdaptor(RangeT values, LateInst op) : Base(op), odsOperands(values) {}

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index) {
    return Base::getODSOperandIndexAndLength(index, odsOperands.size());
  }

  RangeT getODSOperands(unsigned index) {
    auto valueRange = getODSOperandIndexAndLength(index);
    return {std::next(odsOperands.begin(), valueRange.first),
             std::next(odsOperands.begin(), valueRange.first + valueRange.second)};
  }

  RangeT getOperands() {
    return odsOperands;
  }

private:
  RangeT odsOperands;
};
class GlobalTensorOpAdaptor : public GlobalTensorOpGenericAdaptor<::mlir::ValueRange> {
public:
  using GlobalTensorOpGenericAdaptor::GlobalTensorOpGenericAdaptor;
  GlobalTensorOpAdaptor(GlobalTensorOp op);

  ::mlir::LogicalResult verify(::mlir::Location loc);
};
class GlobalTensorOp : public ::mlir::Op<GlobalTensorOp, ::mlir::OpTrait::ZeroRegions, ::mlir::OpTrait::ZeroResults, ::mlir::OpTrait::ZeroSuccessors, ::mlir::OpTrait::ZeroOperands, ::mlir::OpTrait::OpInvariants> {
public:
  using Op::Op;
  using Op::print;
  using Adaptor = GlobalTensorOpAdaptor;
  template <typename RangeT>
  using GenericAdaptor = GlobalTensorOpGenericAdaptor<RangeT>;
  using FoldAdaptor = GenericAdaptor<::llvm::ArrayRef<::mlir::Attribute>>;
  static ::llvm::ArrayRef<::llvm::StringRef> getAttributeNames() {
    static ::llvm::StringRef attrNames[] = {::llvm::StringRef("is_mutable"), ::llvm::StringRef("sym_name"), ::llvm::StringRef("type"), ::llvm::StringRef("value")};
    return ::llvm::ArrayRef(attrNames);
  }

  ::mlir::StringAttr getIsMutableAttrName() {
    return getAttributeNameForIndex(0);
  }

  static ::mlir::StringAttr getIsMutableAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 0);
  }

  ::mlir::StringAttr getSymNameAttrName() {
    return getAttributeNameForIndex(1);
  }

  static ::mlir::StringAttr getSymNameAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 1);
  }

  ::mlir::StringAttr getTypeAttrName() {
    return getAttributeNameForIndex(2);
  }

  static ::mlir::StringAttr getTypeAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 2);
  }

  ::mlir::StringAttr getValueAttrName() {
    return getAttributeNameForIndex(3);
  }

  static ::mlir::StringAttr getValueAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 3);
  }

  static constexpr ::llvm::StringLiteral getOperationName() {
    return ::llvm::StringLiteral("tf_saved_model.global_tensor");
  }

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index);
  ::mlir::Operation::operand_range getODSOperands(unsigned index);
  std::pair<unsigned, unsigned> getODSResultIndexAndLength(unsigned index);
  ::mlir::Operation::result_range getODSResults(unsigned index);
  ::mlir::StringAttr getSymNameAttr();
  ::llvm::StringRef getSymName();
  ::mlir::ElementsAttr getValueAttr();
  ::std::optional< ::mlir::ElementsAttr > getValue();
  ::mlir::TypeAttr getTypeAttr();
  ::mlir::Type getType();
  ::mlir::UnitAttr getIsMutableAttr();
  bool getIsMutable();
  void setSymNameAttr(::mlir::StringAttr attr);
  void setSymName(::llvm::StringRef attrValue);
  void setValueAttr(::mlir::ElementsAttr attr);
  void setTypeAttr(::mlir::TypeAttr attr);
  void setType(::mlir::Type attrValue);
  void setIsMutableAttr(::mlir::UnitAttr attr);
  void setIsMutable(bool attrValue);
  ::mlir::Attribute removeValueAttr();
  ::mlir::Attribute removeIsMutableAttr();
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::StringAttr sym_name, /*optional*/::mlir::ElementsAttr value, ::mlir::TypeAttr type, /*optional*/::mlir::UnitAttr is_mutable);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::StringAttr sym_name, /*optional*/::mlir::ElementsAttr value, ::mlir::TypeAttr type, /*optional*/::mlir::UnitAttr is_mutable);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::llvm::StringRef sym_name, /*optional*/::mlir::ElementsAttr value, ::mlir::Type type, /*optional*/bool is_mutable = false);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::llvm::StringRef sym_name, /*optional*/::mlir::ElementsAttr value, ::mlir::Type type, /*optional*/bool is_mutable = false);
  static void build(::mlir::OpBuilder &, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::ValueRange operands, ::llvm::ArrayRef<::mlir::NamedAttribute> attributes = {});
  ::mlir::LogicalResult verifyInvariantsImpl();
  ::mlir::LogicalResult verifyInvariants();
  ::mlir::LogicalResult verify();
private:
  ::mlir::StringAttr getAttributeNameForIndex(unsigned index) {
    return getAttributeNameForIndex((*this)->getName(), index);
  }

  static ::mlir::StringAttr getAttributeNameForIndex(::mlir::OperationName name, unsigned index) {
    assert(index < 4 && "invalid attribute index");
    assert(name.getStringRef() == getOperationName() && "invalid operation name");
    return name.getAttributeNames()[index];
  }

public:
};
} // namespace tf_saved_model
} // namespace mlir
MLIR_DECLARE_EXPLICIT_TYPE_ID(::mlir::tf_saved_model::GlobalTensorOp)

namespace mlir {
namespace tf_saved_model {

//===----------------------------------------------------------------------===//
// ::mlir::tf_saved_model::SessionInitializerOp declarations
//===----------------------------------------------------------------------===//

namespace detail {
class SessionInitializerOpGenericAdaptorBase {
public:
protected:
  ::mlir::DictionaryAttr odsAttrs;
  ::std::optional<::mlir::OperationName> odsOpName;
  ::mlir::RegionRange odsRegions;
public:
  SessionInitializerOpGenericAdaptorBase(::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {});

  SessionInitializerOpGenericAdaptorBase(SessionInitializerOp op);

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index, unsigned odsOperandsSize);
  ::mlir::DictionaryAttr getAttributes();
  ::mlir::ArrayAttr getInitializersAttr();
  ::mlir::ArrayAttr getInitializers();
};
} // namespace detail
template <typename RangeT>
class SessionInitializerOpGenericAdaptor : public detail::SessionInitializerOpGenericAdaptorBase {
  using ValueT = ::llvm::detail::ValueOfRange<RangeT>;
  using Base = detail::SessionInitializerOpGenericAdaptorBase;
public:
  SessionInitializerOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs = nullptr, const ::mlir::EmptyProperties &properties = {}, ::mlir::RegionRange regions = {}) : Base(attrs, properties, regions), odsOperands(values) {}

  SessionInitializerOpGenericAdaptor(RangeT values, ::mlir::DictionaryAttr attrs, ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions = {}) : SessionInitializerOpGenericAdaptor(values, attrs, (properties ? *properties.as<::mlir::EmptyProperties *>() : ::mlir::EmptyProperties{}), regions) {}

  template <typename LateInst = SessionInitializerOp, typename = std::enable_if_t<std::is_same_v<LateInst, SessionInitializerOp>>>
  SessionInitializerOpGenericAdaptor(RangeT values, LateInst op) : Base(op), odsOperands(values) {}

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index) {
    return Base::getODSOperandIndexAndLength(index, odsOperands.size());
  }

  RangeT getODSOperands(unsigned index) {
    auto valueRange = getODSOperandIndexAndLength(index);
    return {std::next(odsOperands.begin(), valueRange.first),
             std::next(odsOperands.begin(), valueRange.first + valueRange.second)};
  }

  RangeT getOperands() {
    return odsOperands;
  }

private:
  RangeT odsOperands;
};
class SessionInitializerOpAdaptor : public SessionInitializerOpGenericAdaptor<::mlir::ValueRange> {
public:
  using SessionInitializerOpGenericAdaptor::SessionInitializerOpGenericAdaptor;
  SessionInitializerOpAdaptor(SessionInitializerOp op);

  ::mlir::LogicalResult verify(::mlir::Location loc);
};
class SessionInitializerOp : public ::mlir::Op<SessionInitializerOp, ::mlir::OpTrait::ZeroRegions, ::mlir::OpTrait::ZeroResults, ::mlir::OpTrait::ZeroSuccessors, ::mlir::OpTrait::ZeroOperands, ::mlir::OpTrait::OpInvariants> {
public:
  using Op::Op;
  using Op::print;
  using Adaptor = SessionInitializerOpAdaptor;
  template <typename RangeT>
  using GenericAdaptor = SessionInitializerOpGenericAdaptor<RangeT>;
  using FoldAdaptor = GenericAdaptor<::llvm::ArrayRef<::mlir::Attribute>>;
  static ::llvm::ArrayRef<::llvm::StringRef> getAttributeNames() {
    static ::llvm::StringRef attrNames[] = {::llvm::StringRef("initializers")};
    return ::llvm::ArrayRef(attrNames);
  }

  ::mlir::StringAttr getInitializersAttrName() {
    return getAttributeNameForIndex(0);
  }

  static ::mlir::StringAttr getInitializersAttrName(::mlir::OperationName name) {
    return getAttributeNameForIndex(name, 0);
  }

  static constexpr ::llvm::StringLiteral getOperationName() {
    return ::llvm::StringLiteral("tf_saved_model.session_initializer");
  }

  std::pair<unsigned, unsigned> getODSOperandIndexAndLength(unsigned index);
  ::mlir::Operation::operand_range getODSOperands(unsigned index);
  std::pair<unsigned, unsigned> getODSResultIndexAndLength(unsigned index);
  ::mlir::Operation::result_range getODSResults(unsigned index);
  ::mlir::ArrayAttr getInitializersAttr();
  ::mlir::ArrayAttr getInitializers();
  void setInitializersAttr(::mlir::ArrayAttr attr);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::ArrayAttr initializers);
  static void build(::mlir::OpBuilder &odsBuilder, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::ArrayAttr initializers);
  static void build(::mlir::OpBuilder &, ::mlir::OperationState &odsState, ::mlir::TypeRange resultTypes, ::mlir::ValueRange operands, ::llvm::ArrayRef<::mlir::NamedAttribute> attributes = {});
  ::mlir::LogicalResult verifyInvariantsImpl();
  ::mlir::LogicalResult verifyInvariants();
  ::mlir::LogicalResult verify();
  static void getCanonicalizationPatterns(::mlir::RewritePatternSet &results, ::mlir::MLIRContext *context);
private:
  ::mlir::StringAttr getAttributeNameForIndex(unsigned index) {
    return getAttributeNameForIndex((*this)->getName(), index);
  }

  static ::mlir::StringAttr getAttributeNameForIndex(::mlir::OperationName name, unsigned index) {
    assert(index < 1 && "invalid attribute index");
    assert(name.getStringRef() == getOperationName() && "invalid operation name");
    return name.getAttributeNames()[index];
  }

public:
};
} // namespace tf_saved_model
} // namespace mlir
MLIR_DECLARE_EXPLICIT_TYPE_ID(::mlir::tf_saved_model::SessionInitializerOp)


#endif  // GET_OP_CLASSES
