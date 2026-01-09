# Makefile for Cerise Desktop Project

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = cerise_menu
SRC = cerise_menu.c

.PHONY: all clean install run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)
	@echo "✅ Compilação concluída!"
	@echo "   Execute com: ./$(TARGET)"

clean:
	rm -f $(TARGET)
	rm -rf logs/*.log
	@echo "🧹 Limpeza concluída!"

install: $(TARGET)
	@echo "📦 Instalando $(TARGET)..."
	sudo cp $(TARGET) /usr/local/bin/
	@echo "✅ Instalado em /usr/local/bin/$(TARGET)"
	@echo "   Agora você pode executar 'cerise_menu' de qualquer lugar!"

uninstall:
	@echo "🗑️  Desinstalando $(TARGET)..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✅ Desinstalação concluída!"

run: $(TARGET)
	./$(TARGET)

help:
	@echo "Cerise Desktop Project - Makefile"
	@echo ""
	@echo "Alvos disponíveis:"
	@echo "  make          - Compila o programa"
	@echo "  make clean    - Remove executável e logs"
	@echo "  make install  - Instala em /usr/local/bin"
	@echo "  make uninstall- Remove de /usr/local/bin"
	@echo "  make run      - Compila e executa"
	@echo "  make help     - Mostra esta mensagem"
