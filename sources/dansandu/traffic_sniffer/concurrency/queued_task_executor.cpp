#include "dansandu/traffic_sniffer/concurrency/queued_task_executor.hpp"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace dansandu::traffic_sniffer::concurrency::queued_task_executor
{

QueuedTaskExecutor::QueuedTaskExecutor() : state_{State::ready}, taskConsumer_{&QueuedTaskExecutor::consumeTasks, this}
{
}

QueuedTaskExecutor::~QueuedTaskExecutor()
{
    auto lock = std::unique_lock<std::mutex>{mutex_};
    if (state_ == State::ready)
    {
        state_ = State::destroyed;
        lock.unlock();
        conditionVariable_.notify_one();
        taskConsumer_.join();
    }
}

void QueuedTaskExecutor::addTask(std::function<void()> task)
{
    auto lock = std::unique_lock<std::mutex>{mutex_};
    if (state_ == State::ready)
    {
        tasks_.emplace_back(std::move(task));
        lock.unlock();
        conditionVariable_.notify_one();
    }
}

void QueuedTaskExecutor::waitForTasksAndClose()
{
    auto lock = std::unique_lock<std::mutex>{mutex_};
    if (state_ == State::ready)
    {
        state_ = State::closed;
        lock.unlock();
        conditionVariable_.notify_one();
        taskConsumer_.join();
    }
}

void QueuedTaskExecutor::consumeTasks()
{
    auto lock = std::unique_lock<std::mutex>{mutex_};
    while (true)
    {
        conditionVariable_.wait(lock, [this]() { return state_ != State::ready || !tasks_.empty(); });
        if (state_ == State::destroyed || (state_ == State::closed && tasks_.empty()))
        {
            break;
        }
        auto currentBatch = std::move(tasks_);
        lock.unlock();

        for (auto& task : currentBatch)
        {
            try
            {
                task();
            }
            catch (const std::exception&)
            {
                // should write to a log
            }
        }

        lock.lock();
    }
}

}
