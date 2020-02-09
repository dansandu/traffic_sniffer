#include "catchorg/catch/catch.hpp"
#include "dansandu/traffic_sniffer/concurrency/queued_task_executor.hpp"

#include <string>

using dansandu::traffic_sniffer::concurrency::queued_task_executor::QueuedTaskExecutor;

TEST_CASE("QueuedTaskExecutor")
{
    SECTION("processes added tasks in order")
    {
        std::string executedTasks;
        QueuedTaskExecutor queuedTaskExecutor;
        queuedTaskExecutor.addTask([&executedTasks]() { executedTasks += "task#1 "; });
        queuedTaskExecutor.addTask([&executedTasks]() { executedTasks += "task#2 "; });
        queuedTaskExecutor.addTask([&executedTasks]() { executedTasks += "task#3 "; });
        queuedTaskExecutor.waitForTasksAndClose();

        REQUIRE(executedTasks == "task#1 task#2 task#3 ");

        SECTION("tasks added after waitForTasksAndClose are ignored")
        {
            queuedTaskExecutor.addTask([&executedTasks]() { executedTasks += "task#4 "; });
            queuedTaskExecutor.addTask([&executedTasks]() { executedTasks += "task#5 "; });
            queuedTaskExecutor.waitForTasksAndClose();

            REQUIRE(executedTasks == "task#1 task#2 task#3 ");
        }
    }
}
