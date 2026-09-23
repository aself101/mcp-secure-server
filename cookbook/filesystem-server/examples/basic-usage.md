# Basic Usage Examples

This document shows common usage patterns for the filesystem server.

## Reading Files

### Read a text file

```text
Tool: read-file
Arguments: { "filepath": "data/sample.txt" }
```

Response:
```json
{
  "path": "data/sample.txt",
  "normalizedPath": "data/sample.txt",
  "size": 289,
  "content": "This is a sample text file...",
  "encoding": "utf-8"
}
```

### Read a JSON configuration file

```text
Tool: read-file
Arguments: { "filepath": "data/config.json" }
```

Response:
```json
{
  "path": "data/config.json",
  "size": 156,
  "content": "{\n  \"app\": {\n    \"name\": \"Sample Application\"...",
  "encoding": "utf-8"
}
```

### Read from nested directories

```text
Tool: read-file
Arguments: { "filepath": "documents/nested/deep-file.txt" }
```

## Listing Directories

### List the data directory

```text
Tool: list-directory
Arguments: { "path": "data" }
```

Response:
```json
{
  "path": "data",
  "totalEntries": 3,
  "returnedEntries": 3,
  "truncated": false,
  "entries": [
    { "name": "config.json", "type": "file", "size": 156, "modified": "2024-01-15T..." },
    { "name": "sample.txt", "type": "file", "size": 289, "modified": "2024-01-15T..." },
    { "name": "users.json", "type": "file", "size": 385, "modified": "2024-01-15T..." }
  ]
}
```

### List directory with subdirectories

```text
Tool: list-directory
Arguments: { "path": "documents" }
```

Response shows directories first, then files:
```json
{
  "entries": [
    { "name": "nested", "type": "directory" },
    { "name": "readme.md", "type": "file", "size": 245 },
    { "name": "report.txt", "type": "file", "size": 512 }
  ]
}
```

## Searching Files

### Search for a keyword

```text
Tool: search-files
Arguments: { "pattern": "Alice", "directory": "data" }
```

Response:
```json
{
  "pattern": "Alice",
  "directory": "data",
  "filesScanned": 3,
  "filesWithMatches": 1,
  "totalMatches": 1,
  "results": [
    {
      "file": "data/users.json",
      "matches": [
        {
          "line": 5,
          "column": 15,
          "content": "      \"name\": \"Alice Johnson\","
        }
      ]
    }
  ]
}
```

### Search across multiple files

```text
Tool: search-files
Arguments: { "pattern": "sample", "directory": "data" }
```

## Writing Logs

### Write an info log

```text
Tool: write-log
Arguments: { "message": "User action completed", "level": "info" }
```

Response:
```json
{
  "success": true,
  "level": "info",
  "message": "User action completed",
  "file": "app-2024-01-15.log",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Write an error log

```text
Tool: write-log
Arguments: { "message": "Failed to process request: timeout", "level": "error" }
```

### Write a debug log

```text
Tool: write-log
Arguments: { "message": "Processing item 42 of 100", "level": "debug" }
```

## Workflow Example: Data Analysis

1. List available data files:
```text
Tool: list-directory
Arguments: { "path": "data" }
```

2. Search for relevant data:
```text
Tool: search-files
Arguments: { "pattern": "admin", "directory": "data" }
```

3. Read the matching file:
```text
Tool: read-file
Arguments: { "filepath": "data/users.json" }
```

4. Log the analysis:
```text
Tool: write-log
Arguments: { "message": "Analyzed users.json - found 1 admin user", "level": "info" }
```
