#ifndef __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__
#define __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__

#include "base/statistics.hh"
#include "base/stats/group.hh"

#include "mem/packet.hh"
#include "mem/port.hh"
#include "params/SecureMemory.hh"
#include "sim/clocked_object.hh"
#include "sim/eventq.hh"

#include <queue>
#include <algorithm>

#define ARITY 8
#define BLOCK_SIZE 64
#define HMAC_SIZE 8
#define PAGE_SIZE 4096


namespace gem5
{

class SecureMemory : public ClockedObject
{
  private:
    int bufferEntries;
    int responseBufferEntries;

    class CPUSidePort: public ResponsePort
    {
      private:
        SecureMemory* owner;
        bool needToSendRetry;
        PacketPtr blockedPacket;

      public:
        CPUSidePort(SecureMemory* owner, const std::string& name):
            ResponsePort(name), owner(owner), needToSendRetry(false), blockedPacket(nullptr)
        {}
        bool needRetry() const { return needToSendRetry; }
        bool blocked() const { return blockedPacket != nullptr; }
        void sendPacket(PacketPtr pkt);

        virtual AddrRangeList getAddrRanges() const override;
        virtual bool recvTimingReq(PacketPtr pkt) override;
        virtual Tick recvAtomic(PacketPtr pkt) override;
        virtual void recvFunctional(PacketPtr pkt) override;
        virtual void recvRespRetry() override;
    };

    class MemSidePort: public RequestPort
    {
      private:
        SecureMemory* owner;
        bool needToSendRetry;
        PacketPtr blockedPacket;

      public:
        MemSidePort(SecureMemory* owner, const std::string& name):
            RequestPort(name), owner(owner), needToSendRetry(false), blockedPacket(nullptr)
        {}
        bool needRetry() const { return needToSendRetry; }
        bool blocked() const { return blockedPacket != nullptr; }
        void sendPacket(PacketPtr pkt);

        virtual bool recvTimingResp(PacketPtr pkt) override;
        virtual void recvReqRetry() override;
    };

    template<typename T>
    class TimedQueue
    {
      private:
          Tick latency;

          std::queue<T> items;
          std::queue<Tick> insertionTimes;

      public:
          TimedQueue(Tick latency): latency(latency) {}

          void push(T item, Tick insertion_time) {
              items.push(item);
              insertionTimes.push(insertion_time);
          }
          void pop() {
              items.pop();
              insertionTimes.pop();
          }

          T& front() { return items.front(); }
          bool empty() const { return items.empty(); }
          size_t size() const { return items.size(); }
          bool hasReady(Tick current_time) const {
              if (empty()) {
                  return false;
              }
              return (current_time - insertionTimes.front()) >= latency;
          }
          Tick firstReadyTime() { return insertionTimes.front() + latency; }
          Tick frontTime() { return insertionTimes.front(); }
    };

    CPUSidePort cpuSidePort;
    MemSidePort memSidePort;
    TimedQueue<PacketPtr> buffer;

    struct SecureMemoryStats: public statistics::Group
    {
        statistics::Scalar totalbufferLatency;
        statistics::Scalar numRequestsFwded;
        statistics::Scalar totalResponseBufferLatency;
        statistics::Scalar numResponsesFwded;
        SecureMemoryStats(SecureMemory* secure_memory);
    };
    SecureMemoryStats stats;

    //For Request (mem_side)
    //Evento para el pasaje de CPU_side a MEM_side
    EventFunctionWrapper nextReqSendEvent;
    void processNextReqSendEvent();
    void scheduleNextReqSendEvent(Tick when);
    //Evento para reintentar procesar el paquete (que te habia llegado y estabas busy)
    EventFunctionWrapper nextReqRetryEvent;
    void processNextReqRetryEvent();
    void scheduleNextReqRetryEvent(Tick when);

    //For Response (CPU_side)
    TimedQueue<PacketPtr> responseBuffer;
    EventFunctionWrapper nextRespSendEvent;
    EventFunctionWrapper nextRespRetryEvent;
    void processNextRespSendEvent();
    void scheduleNextRespSendEvent(Tick when);
    void processNextRespRetryEvent();
    void scheduleNextRespRetryEvent(Tick when);
    void recvRespRetry();

    Tick align(Tick when);

        std::deque<uint64_t> integrity_levels;

    // Merkle Tree
    // variables to help refer to certain metadata types
    int root_level = 1;
    int hmac_level = 0;
    int data_level; // set after object construction in setup()
    int counter_level; // set after object construction in setup()
    // structures to know what is currently pending authentication, etc
    std::set<uint64_t> pending_tree_authentication;
    // a bit of a misnomer, we'll use this for hmacs so all tree nodes
    // can go to pending_authentications
    std::set<uint64_t> pending_hmac;
    // fetched but not verified OR writes waiting for path to update
    std::set<PacketPtr> pending_untrusted_packets;
    // secure memory functions
    uint64_t getHmacAddr(uint64_t child_addr); // fetch address of the hmac for somed data
    uint64_t getParentAddr(uint64_t child_addr); // fetch parent node in the tree
    void verifyChildren(PacketPtr parent); // remove children from pending untrusted once trusted
    bool handleResponse(PacketPtr pkt) ;
    bool handleRequest(PacketPtr pkt);

  public:
    SecureMemory(const SecureMemoryParams& params);
    virtual Port& getPort(const std::string& if_name, PortID idxInvalidPortID);

    AddrRangeList getAddrRanges() const;
    bool recvTimingReq(PacketPtr pkt);
    Tick recvAtomic(PacketPtr pkt);
    void recvFunctional(PacketPtr pkt);
    void recvReqRetry();

    bool recvTimingResp(PacketPtr pkt);
    virtual void init() override;


};


} // namespace gem5

#endif // __BOOTCAMP_SECURE_MEMORY_SECURE_MEMORY_HH__
