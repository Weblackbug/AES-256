#pragma once

#include "resource.h"

void Autor(HWND hWnd);
std::wstring PedirPassword(HWND hWnd);
bool CifrarAES256(const unsigned char* buffer,
	size_t bufferLen, const std::wstring& password,
	std::vector<unsigned char>& bufferCifrado);
// Descifra un buffer usando AES-256 CBC y almacena el resultado en bufferDescifrado
bool DescifrarAES256(const unsigned char* buffer, size_t bufferLen,
	const std::wstring& password,
	std::vector<unsigned char>& bufferDescifrado);
bool GuardarFichero(HWND hWnd);