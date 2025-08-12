#!/usr/bin/env python3
"""
Test the path matching logic independently.
"""

import re

def path_matches(pattern_path: str, actual_path: str) -> bool:
    """
    Check if an actual path matches a pattern path.
    Supports basic path parameter matching with {param} syntax.
    """
    # Simple exact match first
    if pattern_path == actual_path:
        return True
    
    # Convert pattern to regex for parameter matching
    # Replace {param} with [^/]+ to match any non-slash characters
    pattern_regex = re.sub(r'\{[^}]+\}', r'[^/]+', pattern_path)
    pattern_regex = f"^{pattern_regex}$"
    
    return bool(re.match(pattern_regex, actual_path))

def test_path_matching():
    """Test the path matching logic."""
    print("Testing Path Matching Logic")
    print("=" * 40)
    
    test_cases = [
        ("/users/{username}", "/users/john", True),
        ("/users/{username}", "/users/jane", True), 
        ("/users/{username}/groups", "/users/john/groups", True),
        ("/users", "/users", True),
        ("/users/{username}", "/posts/123", False),
        ("/api/v1/users/{id}", "/api/v1/users/123", True),
        ("/users/{id}/posts/{postId}", "/users/123/posts/456", True),
        ("/users/{id}/posts/{postId}", "/users/123/comments/456", False),
    ]
    
    passed = 0
    total = len(test_cases)
    
    for pattern, actual, expected in test_cases:
        result = path_matches(pattern, actual)
        status = "✅ PASS" if result == expected else "❌ FAIL"
        print(f"{status} | Pattern: {pattern:<25} | Actual: {actual:<25} | Expected: {expected} | Got: {result}")
        if result == expected:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")

if __name__ == "__main__":
    test_path_matching()
