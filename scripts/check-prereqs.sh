#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          KernelHarbor - Prerequisite Checker             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_elasticsearch() {
    echo -e "${CYAN}${BOLD}[1/3] Checking Elasticsearch...${NC}"
    
    ES_ADDR="${ES_ADDRESSES:-http://localhost:9200}"
    
    if curl -s -f "${ES_ADDR}" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Elasticsearch is running at ${ES_ADDR}${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Elasticsearch not running at ${ES_ADDR}${NC}"
        echo -e "${YELLOW}  Attempting to start via Docker...${NC}"
        
        if command -v docker &> /dev/null; then
            if docker ps --format '{{.Names}}' | grep -q "^elasticsearch$"; then
                echo -e "${GREEN}✓ Starting existing Elasticsearch container...${NC}"
                docker start elasticsearch
            else
                echo -e "${YELLOW}Starting new Elasticsearch container...${NC}"
                docker run -d --name elasticsearch \
                    -p 9200:9200 -p 9300:9300 \
                    -e "discovery.type=single-node" \
                    -e "xpack.security.enabled=false" \
                    -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
                    docker.elastic.co/elasticsearch/elasticsearch:8.11.0
            fi
            
            echo -e "${YELLOW}  Waiting for Elasticsearch to be ready...${NC}"
            for i in {1..30}; do
                if curl -s -f "${ES_ADDR}" > /dev/null 2>&1; then
                    echo -e "${GREEN}✓ Elasticsearch is ready!${NC}"
                    return 0
                fi
                sleep 2
            done
            echo -e "${RED}✗ Elasticsearch failed to start${NC}"
            return 1
        else
            echo -e "${RED}✗ Docker not found. Please start Elasticsearch manually.${NC}"
            return 1
        fi
    fi
}

check_ollama() {
    echo -e "${CYAN}${BOLD}[2/3] Checking Ollama...${NC}"
    
    OLLAMA_ADDR="${OLLAMA_ADDRESS:-http://localhost:11434}"
    
    if curl -s -f "${OLLAMA_ADDR}/api/tags" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Ollama is running at ${OLLAMA_ADDR}${NC}"
        
        MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
        echo -e "${CYAN}  Checking for model: ${MODEL}${NC}"
        
        if curl -s "${OLLAMA_ADDR}/api/tags" | grep -q "\"${MODEL}\""; then
            echo -e "${GREEN}✓ Model '${MODEL}' is available${NC}"
        else
            echo -e "${YELLOW}⚠ Pulling model '${MODEL}' (this may take a few minutes)...${NC}"
            curl -s "${OLLAMA_ADDR}/api/pull" -d "{\"name\": \"${MODEL}\"}" > /dev/null &
            echo -e "${YELLOW}  Model pull started in background${NC}"
        fi
        return 0
    else
        echo -e "${YELLOW}⚠ Ollama not running at ${OLLAMA_ADDR}${NC}"
        echo -e "${YELLOW}  Attempting to start Ollama server...${NC}"
        
        if command -v ollama &> /dev/null; then
            ollama serve &
            OLLAMA_PID=$!
            
            echo -e "${YELLOW}  Waiting for Ollama to be ready...${NC}"
            for i in {1..30}; do
                if curl -s -f "${OLLAMA_ADDR}/api/tags" > /dev/null 2>&1; then
                    echo -e "${GREEN}✓ Ollama is ready!${NC}"
                    
                    MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
                    echo -e "${YELLOW}  Pulling model '${MODEL}' (first run)...${NC}"
                    ollama pull "${MODEL}" 2>/dev/null || true
                    return 0
                fi
                sleep 2
            done
            echo -e "${RED}✗ Ollama failed to start${NC}"
            return 1
        else
            echo -e "${RED}✗ Ollama not found. Please install Ollama first.${NC}"
            return 1
        fi
    fi
}

check_grpc_port() {
    echo -e "${CYAN}${BOLD}[3/3] Checking gRPC availability...${NC}"
    
    GRPC_ADDR="${GRPC_ADDRESS:-localhost:9090}"
    
    if command -v nc &> /dev/null; then
        if nc -z localhost 9090 2>/dev/null; then
            echo -e "${YELLOW}⚠ Port 9090 already in use${NC}"
            return 1
        fi
    fi
    
    echo -e "${GREEN}✓ Port 9090 is available for gRPC${NC}"
    return 0
}

print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗"
    echo -e "║              All prerequisites ready! ✓                 ║"
    echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo -e "  ${YELLOW}1.${NC} Terminal 1: ${GREEN}./scripts/start-analysis.sh${NC}"
    echo -e "  ${YELLOW}2.${NC} Terminal 2: ${GREEN}sudo ./scripts/start-agent.sh${NC}"
    echo ""
}

main() {
    print_banner
    
    check_elasticsearch
    check_ollama
    check_grpc_port
    
    print_summary
}

main "$@"
