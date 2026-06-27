package dev.cake.auth.task;

import java.time.Duration;
import java.time.Instant;

final class TaskFixtures {

    static final String NAME = "clear garden";
    static final String DESCRIPTION = "eliminate crop bags";
    static final Instant DEADLINE = Instant.now().plus(Duration.ofHours(1));

    static final String UPDATED_NAME = "tidy garden";
    static final String UPDATED_DESCRIPTION = "dayum";
    static final TaskStatus UPDATED_STATUS = TaskStatus.CANCELED;
    static final Instant UPDATED_DEADLINE = Instant.now().plus(Duration.ofHours(2));

    private TaskFixtures() {
    }

    static CreateTaskRequestBuilder aCreateTaskRequest() {
        return new CreateTaskRequestBuilder();
    }

    static UpdateTaskRequestBuilder anUpdateTaskRequest() {
        return new UpdateTaskRequestBuilder();
    }

    static final class CreateTaskRequestBuilder {
        private String name = NAME;
        private String description = DESCRIPTION;
        private Instant deadline = DEADLINE;

        CreateTaskRequestBuilder name(String name) {
            this.name = name;
            return this;
        }

        CreateTaskRequestBuilder description(String description) {
            this.description = description;
            return this;
        }

        CreateTaskRequestBuilder deadline(Instant deadline) {
            this.deadline = deadline;
            return this;
        }

        CreateTaskRequest build() {
            return new CreateTaskRequest(name, description, deadline);
        }
    }

    static final class UpdateTaskRequestBuilder {
        private String name = UPDATED_NAME;
        private String description = UPDATED_DESCRIPTION;
        private TaskStatus status = UPDATED_STATUS;
        private Instant deadline = UPDATED_DEADLINE;

        UpdateTaskRequestBuilder name(String name) {
            this.name = name;
            return this;
        }

        UpdateTaskRequestBuilder description(String description) {
            this.description = description;
            return this;
        }

        UpdateTaskRequestBuilder status(TaskStatus status) {
            this.status = status;
            return this;
        }

        UpdateTaskRequestBuilder deadline(Instant deadline) {
            this.deadline = deadline;
            return this;
        }

        UpdateTaskRequest build() {
            return new UpdateTaskRequest(name, description, status, deadline);
        }
    }
}
