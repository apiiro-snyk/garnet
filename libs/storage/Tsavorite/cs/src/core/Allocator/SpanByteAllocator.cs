﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

namespace Tsavorite.core
{
    // Allocator for SpanByte, possibly with a Blittable Key or Value.
    internal struct SpanByteAllocator : IAllocator<SpanByte, SpanByte, SpanByteComparer, NoSerializer<SpanByte>, NoSerializer<SpanByte>, SpanByteRecordDisposer, StoreFunctions_SpanByte>
    {
        /// <summary>
        /// The wrapped class containing all data and most actual functionality. This must be the ONLY field in this structure so its size is sizeof(IntPtr).
        /// </summary>
        private readonly SpanByteAllocatorImpl _this;

        /// <inheritdoc/>
        public readonly StoreFunctions_SpanByte StoreFunctions => _this._storeFunctions;

        /// <inheritdoc/>
        public readonly void Initialize() => _this.Initialize();

        /// <inheritdoc/>
        public readonly long GetStartLogicalAddress(long page) => _this.GetStartLogicalAddress(page);

        /// <inheritdoc/>
        public readonly long GetFirstValidLogicalAddress(long page) => _this.GetFirstValidLogicalAddress(page);

        /// <inheritdoc/>
        public readonly long GetPhysicalAddress(long logicalAddress) => _this.GetPhysicalAddress(logicalAddress);

        /// <inheritdoc/>
        public readonly ref RecordInfo GetInfo(long physicalAddress) => ref SpanByteAllocatorImpl.GetInfo(physicalAddress);

        /// <inheritdoc/>
        public readonly unsafe ref RecordInfo GetInfoFromBytePointer(byte* ptr) => ref SpanByteAllocatorImpl.GetInfoFromBytePointer(ptr);

        /// <inheritdoc/>
        public readonly ref SpanByte GetKey(long physicalAddress) => ref SpanByteAllocatorImpl.GetKey(physicalAddress);

        /// <inheritdoc/>
        public readonly ref SpanByte GetValue(long physicalAddress) => ref _this.GetValue(physicalAddress);

        /// <inheritdoc/>
        public readonly ref SpanByte GetAndInitializeValue(long physicalAddress, long endPhysicalAddress) => ref GetValue(physicalAddress);

        /// <inheritdoc/>
        public readonly (int actualSize, int allocatedSize) GetRecordSize(long physicalAddress) => _this.GetRecordSize(physicalAddress);

        /// <inheritdoc/>
        public readonly (int actualSize, int allocatedSize, int keySize) GetRMWCopyDestinationRecordSize<Input, TVariableLengthInput>(ref SpanByte key, ref Input input, ref SpanByte value, ref RecordInfo recordInfo, TVariableLengthInput varlenInput)
            where TVariableLengthInput : IVariableLengthInput<SpanByte, Input>
             => _this.GetRMWCopyDestinationRecordSize(ref key, ref input, ref value, ref recordInfo, varlenInput);

        /// <inheritdoc/>
        public readonly int GetRequiredRecordSize(long physicalAddress, int availableBytes) => GetAverageRecordSize();

        /// <inheritdoc/>
        public readonly int GetAverageRecordSize() => _this.GetAverageRecordSize();

        /// <inheritdoc/>
        public readonly (int actualSize, int allocatedSize, int keySize) GetRMWInitialRecordSize<Input, TSessionFunctionsWrapper>(ref SpanByte key, ref Input input, TSessionFunctionsWrapper sessionFunctions)
            where TSessionFunctionsWrapper : IVariableLengthInput<SpanByte, Input>
            => _this.GetRMWInitialRecordSize(ref key, ref input, sessionFunctions);

        /// <inheritdoc/>
        public readonly (int actualSize, int allocatedSize, int keySize) GetRecordSize(ref SpanByte key, ref SpanByte value) => _this.GetRecordSize(ref key, ref value);

        /// <inheritdoc/>
        public readonly int GetValueLength(ref SpanByte value) => SpanByteAllocatorImpl.GetValueLength(ref value);

        /// <inheritdoc/>
        public readonly unsafe bool RetrievedFullRecord(byte* record, ref AsyncIOContext<SpanByte, SpanByte> ctx) => SpanByteAllocatorImpl.RetrievedFullRecord(record, ref ctx);

        /// <inheritdoc/>
        public readonly void AllocatePage(int pageIndex) => _this.AllocatePage(pageIndex);

        /// <inheritdoc/>
        public readonly bool IsAllocated(int pageIndex) => _this.IsAllocated(pageIndex);

        /// <inheritdoc/>
        public readonly unsafe void PopulatePage(byte* src, int required_bytes, long destinationPageIndex) => _this.PopulatePage(src, required_bytes, destinationPageIndex);

        /// <inheritdoc/>
        public readonly void MarkPage(long logicalAddress, long version) => _this.MarkPage(logicalAddress, version);

        /// <inheritdoc/>
        public readonly void MarkPageAtomic(long logicalAddress, long version) => _this.MarkPageAtomic(logicalAddress, version);

        /// <inheritdoc/>
        public readonly void ClearPage(long page, int offset = 0) => _this.ClearPage(page, offset);

        /// <inheritdoc/>
        public readonly void FreePage(long pageIndex) => _this.FreePage(pageIndex);

        /// <inheritdoc/>
        public readonly ref SpanByte GetContextRecordKey(ref AsyncIOContext<SpanByte, SpanByte> ctx) => ref ctx.key;

        /// <inheritdoc/>
        public readonly ref SpanByte GetContextRecordValue(ref AsyncIOContext<SpanByte, SpanByte> ctx) => ref ctx.value;

        /// <inheritdoc/>
        public readonly IHeapContainer<SpanByte> GetKeyContainer(ref SpanByte key) => new StandardHeapContainer<SpanByte>(ref key);

        /// <inheritdoc/>
        public readonly IHeapContainer<SpanByte> GetValueContainer(ref SpanByte value) => new StandardHeapContainer<SpanByte>(ref value);

        /// <inheritdoc/>
        public readonly long[] GetSegmentOffsets() => SpanByteAllocatorImpl.GetSegmentOffsets();

        /// <inheritdoc/>
        public readonly int OverflowPageCount => _this.OverflowPageCount;

        /// <inheritdoc/>
        public readonly void EvictPage(long page) => _this.EvictPage(page);

        /// <inheritdoc/>
        public readonly bool TryComplete() => _this.TryComplete();

        /// <inheritdoc/>
        public readonly void SerializeKey(ref SpanByte key, long physicalAddress) => SpanByteAllocatorImpl.SerializeKey(ref key, physicalAddress);
    }
}