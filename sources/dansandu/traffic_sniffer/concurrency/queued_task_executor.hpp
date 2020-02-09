#pragma once

#include "dansandu/ballotin/type_traits.hpp"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace dansandu::traffic_sniffer::concurrency::queued_task_executor
{

class QueuedTaskExecutor : dansandu::ballotin::type_traits::Immovable, dansandu::ballotin::type_traits::Uncopyable
{
public:
    QueuedTaskExecutor();

    ~QueuedTaskExecutor();

    void addTask(std::function<void()> task);

    void waitForTasksAndClose();

private:
    void consumeTasks();

    enum class State
    {
        ready,
        closed,
        destroyed
    };

    std::mutex mutex_;
    State state_;
    std::vector<std::function<void()>> tasks_;
    std::condition_variable conditionVariable_;
    std::thread taskConsumer_;
};

}
