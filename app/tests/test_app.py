"""
Application unit tests for the vulnerable Flask API.
Tests verify functional behavior of all endpoints.
"""

import json
import pytest
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestRootEndpoint:
    """Tests for GET / endpoint."""

    def test_root_returns_json(self, client):
        """Root endpoint returns valid JSON."""
        response = client.get('/')
        assert response.status_code == 200
        assert response.is_json

    def test_root_contains_app_info(self, client):
        """Root response contains application name and version."""
        response = client.get('/')
        data = response.get_json()
        assert 'message' in data
        assert 'version' in data
        assert 'devsecops-pipeline' in data['message']


class TestHealthEndpoint:
    """Tests for GET /health endpoint."""

    def test_health_returns_200(self, client):
        """Health endpoint returns HTTP 200."""
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        """Health endpoint returns valid JSON."""
        response = client.get('/health')
        assert response.is_json

    def test_health_status_healthy(self, client):
        """Health status is 'healthy'."""
        response = client.get('/health')
        data = response.get_json()
        assert data['status'] == 'healthy'


class TestSearchEndpoint:
    """Tests for GET /search endpoint."""

    def test_search_with_query(self, client):
        """Search endpoint accepts query parameter."""
        response = client.get('/search?q=test')
        assert response.status_code == 200
        data = response.get_json()
        assert 'query' in data
        assert data['query'] == 'test'

    def test_search_empty_query(self, client):
        """Search endpoint handles empty query."""
        response = client.get('/search?q=')
        assert response.status_code == 200
        data = response.get_json()
        assert data['query'] == ''

    def test_search_missing_query(self, client):
        """Search endpoint handles missing query parameter."""
        response = client.get('/search')
        assert response.status_code == 200
        data = response.get_json()
        assert 'query' in data


class TestLoginEndpoint:
    """Tests for POST /login endpoint."""

    def test_login_valid_credentials(self, client):
        """Login succeeds with dummy credentials."""
        response = client.post('/login', 
            json={'username': 'admin', 'password': 'password123'})
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'token' in data

    def test_login_invalid_credentials(self, client):
        """Login fails with invalid credentials."""
        response = client.post('/login', 
            json={'username': 'admin', 'password': 'wrong'})
        assert response.status_code == 401
        data = response.get_json()
        assert data['success'] is False

    def test_login_missing_json(self, client):
        """Login fails without JSON content type."""
        response = client.post('/login', data='username=admin&password=test')
        assert response.status_code == 400

    def test_login_missing_fields(self, client):
        """Login handles missing username/password."""
        response = client.post('/login', json={'username': 'admin'})
        assert response.status_code == 200  # Still processes, just fails auth
        data = response.get_json()
        assert data['success'] is False


class TestUserEndpoint:
    """Tests for GET /user endpoint."""

    def test_user_with_name(self, client):
        """User endpoint returns profile for given name."""
        response = client.get('/user?name=john')
        assert response.status_code == 200
        data = response.get_json()
        assert data['name'] == 'john'

    def test_user_empty_name(self, client):
        """User endpoint handles empty name."""
        response = client.get('/user?name=')
        assert response.status_code == 200
        data = response.get_json()
        assert data['name'] == ''


class TestHeadersEndpoint:
    """Tests for GET /headers endpoint."""

    def test_headers_returns_request_headers(self, client):
        """Headers endpoint echoes request headers."""
        response = client.get('/headers')
        assert response.status_code == 200
        data = response.get_json()
        assert 'headers' in data
        assert 'server_info' in data

    def test_headers_contains_user_agent(self, client):
        """Response includes User-Agent from request."""
        response = client.get('/headers')
        data = response.get_json()
        assert 'User-Agent' in data['headers']


class TestErrorHandling:
    """Tests for error handling."""

    def test_404_returns_json(self, client):
        """404 errors return JSON response."""
        response = client.get('/nonexistent')
        assert response.status_code == 404
        assert response.is_json
        data = response.get_json()
        assert 'error' in data

    def test_method_not_allowed(self, client):
        """Unsupported methods return 405."""
        response = client.put('/')
        assert response.status_code == 405


class TestInvalidInput:
    """Tests for malformed input handling."""

    def test_invalid_json(self, client):
        """Invalid JSON payload handled gracefully."""
        response = client.post('/login', 
            data='not json', 
            content_type='application/json')
        assert response.status_code == 400

    def test_large_payload(self, client):
        """Large payload handled appropriately."""
        large_data = {'username': 'a' * 10000, 'password': 'b' * 10000}
        response = client.post('/login', json=large_data)
        assert response.status_code in (200, 401, 413)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])