package dev.cake.auth.task;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;

@Schema(description = "Task representation")
record TaskResponse(
        @Schema(description = "Task identifier", example = "0190f1a2-3b4c-7d8e-9f00-112233445566")
        UUID id,

        @Schema(description = "Task name", example = "Write project report")
        String name,

        @Schema(description = "Task description", example = "Cover Q2 metrics and next steps")
        String description,

        @Schema(description = "Task status", example = "TODO")
        TaskStatus status,

        @Schema(description = "Deadline", example = "2026-07-01T12:00:00Z")
        Instant deadline,

        @Schema(description = "Creation timestamp", example = "2026-06-26T09:30:00Z")
        Instant createdAt,

        @Schema(description = "Last update timestamp", example = "2026-06-26T09:30:00Z")
        Instant updatedAt
) {

    static TaskResponse from(Task task) {
        return new TaskResponse(
                task.getPublicId(),
                task.getName(),
                task.getDescription(),
                task.getStatus(),
                task.getDeadline(),
                task.getCreatedAt(),
                task.getUpdatedAt()
        );
    }

}
