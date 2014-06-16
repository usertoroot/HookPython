#include <Windows.h>
#include <stdio.h>
#include <map>
#include <math.h>

#undef _DEBUG
#include <Python.h>
#define _DEBUG

std::map<void*, void*> _originalFunctionMap;

static PyObject* WriteMemoryInteger(PyObject* self, PyObject* args);
static PyObject* ReadMemoryInteger(PyObject* self, PyObject* args);
static PyObject* WriteMemoryByte(PyObject* self, PyObject* args);
static PyObject* ReadMemoryByte(PyObject* self, PyObject* args);
static PyObject* WriteMemoryString(PyObject* self, PyObject* args);
static PyObject* ReadMemoryString(PyObject* self, PyObject* args);
static PyObject* CallOriginalFunction(PyObject* self, PyObject* args);

int WriteByte(unsigned char* data, int index, unsigned char byte);
int WriteShort(unsigned char* data, int index, unsigned short s);
int WriteInt(unsigned char* data, int index, int i);
int WriteRelativeAddress(unsigned char* data, int index, int address);
int WriteRelativeByteOffset(unsigned char* data, int index, int address);

static PyMethodDef HookPythonMethods[] = {
	{ "WriteMemoryInteger", WriteMemoryInteger, METH_VARARGS, "Write an integer to a memory location." },
	{ "ReadMemoryInteger", ReadMemoryInteger, METH_VARARGS, "Read an integer from a memory location." },
	{ "WriteMemoryByte", WriteMemoryByte, METH_VARARGS, "Write an byte to a memory location." },
	{ "ReadMemoryByte", ReadMemoryByte, METH_VARARGS, "Read an byte from a memory location." },
	{ "WriteMemoryString", WriteMemoryString, METH_VARARGS, "Write a string to a memory location." },
	{ "ReadMemoryString", ReadMemoryString, METH_VARARGS, "Read a string from a memory location." },
	{ "CallOriginalFunction", CallOriginalFunction, METH_VARARGS, "Call the original function." },
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef HookPythonModule = {
	PyModuleDef_HEAD_INIT,
	"HookPython",
	NULL,
	-1,
	HookPythonMethods
};

extern "C" static PyObject* PyInit_HookPython()
{
	return PyModule_Create(&HookPythonModule);
}

void* _stdcall GetOriginalFunctionAddress(void* functionAddress)
{
	std::map<void*, void*>::iterator itr = _originalFunctionMap.find(functionAddress);
	if (itr != _originalFunctionMap.end())
		return itr->second;
	return NULL;
}

static PyObject* WriteMemoryInteger(PyObject* self, PyObject* args)
{
	int address;
	int value;

	if (!PyArg_ParseTuple(args, "ii", &address, &value))
		return NULL;

	*(int*)address = value;
	return Py_BuildValue("i", 1);
}

static PyObject* ReadMemoryInteger(PyObject* self, PyObject* args)
{
	int address;

	if (!PyArg_ParseTuple(args, "i", &address))
		return NULL;

	return Py_BuildValue("i", *(int*)address);
}

static PyObject* WriteMemoryByte(PyObject* self, PyObject* args)
{
	int address;
	int value;

	if (!PyArg_ParseTuple(args, "ii", &address, &value))
		return NULL;

	*(unsigned char*)address = value;
	return Py_BuildValue("i", 1);
}

static PyObject* ReadMemoryByte(PyObject* self, PyObject* args)
{
	int address;

	if (!PyArg_ParseTuple(args, "i", &address))
		return NULL;

	return Py_BuildValue("i", *(unsigned char*)address);
}

static PyObject* WriteMemoryString(PyObject* self, PyObject* args)
{
	int address;
	const char* value;

	if (!PyArg_ParseTuple(args, "is", &address, &value))
		return NULL;

	*(unsigned char*)address = (unsigned char)value;
	return Py_BuildValue("i", 1);
}

static PyObject* ReadMemoryString(PyObject* self, PyObject* args)
{
	int address;

	if (!PyArg_ParseTuple(args, "i", &address))
		return NULL;

	return Py_BuildValue("s",  (char*)address);
}

static PyObject* CallOriginalFunction(PyObject* self, PyObject* args)
{
	PyObject* v = PyObject_GetAttrString(PyImport_AddModule("__main__"), "HookFunctionAddress");
	int hookFunctionAddress = _PyLong_AsInt(v);

	char* format = NULL;
	PyObject* vFormat = PyObject_GetAttrString(PyImport_AddModule("__main__"), "HookFormat");
	if (vFormat)
		format = PyUnicode_AsUTF8(vFormat);

	char* declspec = NULL;
	PyObject* vDeclSpec = PyObject_GetAttrString(PyImport_AddModule("__main__"), "HookDeclSpec");
	if (vDeclSpec)
		declspec = PyUnicode_AsUTF8(vDeclSpec);

	int parameters = PyTuple_Size(args);

	int index = 0;
	unsigned char* function = (unsigned char*)VirtualAlloc(NULL, 512, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	index = WriteByte(function, index, 0x68); //push functionAddress
	index = WriteInt(function, index, (int)hookFunctionAddress);

	index = WriteByte(function, index, 0xE8); //call GetOriginalFunctionAddress
	index = WriteRelativeAddress(function, index, (int)&GetOriginalFunctionAddress);

	index = WriteByte(function, index, 0x83); //cmp eax, 0
	index = WriteByte(function, index, 0xF8);
	index = WriteByte(function, index, 0x00);

	index = WriteByte(function, index, 0x74); //je pastCallOriginal

	//Placeholder
	int jumpIndex = index;
	index = WriteByte(function, index, 0x00);

	for (int i = parameters - 1; i >= (strcmp(declspec, "thiscall") == 0 ? 1 : 0); i--)
	{
		index = WriteByte(function, index, 0x68); //push parameter[i]

		switch (format[i])
		{
		case 'b': //unsigned char
		case 'B': //unsigned char
		case 'h': //short int
		case 'H': //unsigned short int
		case 'i': //int
		case 'I': //unsigned int
		case 'l': //long
		case 'k': //unsigned long
			index = WriteInt(function, index, _PyLong_AsInt(PyTuple_GetItem(args, i)));
			break;
		case 'f': //float
			{
				float f = PyFloat_AsDouble(PyTuple_GetItem(args, i));
				index = WriteInt(function, index, *(int*)&f);
				break;
			}
		case 's': //UTF-8 string
		case 'u': //unicode string
			index = WriteInt(function, index, (int)PyUnicode_AsUTF8(PyTuple_GetItem(args, i)));
			break;
		case 'y': //bytes
			index = WriteInt(function, index, (int)PyBytes_AsString(PyTuple_GetItem(args, i)));
			break;
		default:
		case 'L': //long long
		case 'K': //unsigned long long
		case 'd': //double
			return Py_BuildValue("i", 0);
		}
	}

	if (strcmp(declspec, "thiscall") == 0)
	{
		index = WriteByte(function, index, 0xB9); //mov ecx, value

		switch (format[0])
		{
		case 'b': //unsigned char
		case 'B': //unsigned char
		case 'h': //short int
		case 'H': //unsigned short int
		case 'i': //int
		case 'I': //unsigned int
		case 'l': //long
		case 'k': //unsigned long
			index = WriteInt(function, index, _PyLong_AsInt(PyTuple_GetItem(args, 0)));
			break;
		case 'f': //float
		{
					  float f = PyFloat_AsDouble(PyTuple_GetItem(args, 0));
					  index = WriteInt(function, index, *(int*)&f);
					  break;
		}
		case 's': //UTF-8 string
		case 'u': //unicode string
			index = WriteInt(function, index, (int)PyUnicode_AsUTF8(PyTuple_GetItem(args, 0)));
			break;
		case 'y': //bytes
			index = WriteInt(function, index, (int)PyBytes_AsString(PyTuple_GetItem(args, 0)));
			break;
		default:
		case 'L': //long long
		case 'K': //unsigned long long
		case 'd': //double
			return Py_BuildValue("i", 0);
		}
	}

	index = WriteByte(function, index, 0xFF); //call eax
	index = WriteByte(function, index, 0xD0);

	if (strcmp(declspec, "cdecl") == 0)
	{
		index = WriteByte(function, index, 0x83); //add esp, 4 * parameters
		index = WriteByte(function, index, 0xC4);
		index = WriteByte(function, index, 4 * parameters);
	}

	WriteRelativeByteOffset(function, jumpIndex, (int)(function + index));

	index = WriteByte(function, index, 0xC3); //return

	void* result = ((void* (_cdecl *)())function)();

	VirtualFree(function, NULL, MEM_FREE);
	return Py_BuildValue("i", (int)result);
}

void _cdecl CallPythonFunction(int hookFunctionAddress, const char* functionName, const char* declspec, const char* format, int parameters, void* firstParameter)
{
	Py_Initialize();

	char number[32];
	char parameterString[64];
	parameterString[0] = '\0';
	for (int i = 0; i < parameters; i++)
	{
		if (i > 0)
			strcat_s(parameterString, ", ");

		if (format)
		{
			switch (format[i])
			{
			case 'b': //unsigned char
			case 'B': //unsigned char
			case 'h': //short int
			case 'H': //unsigned short int
			case 'i': //int
			case 'I': //unsigned int
			case 'l': //long
			case 'k': //unsigned long
				itoa(*((int*)&firstParameter + i), number, 10);
				strcat_s(parameterString, number);
				break;
			case 'f': //float
				sprintf_s(number, "%f", *((float*)((int*)&firstParameter + i)));
				strcat_s(parameterString, number);
				break;
			case 's': //UTF-8 string
			case 'u': //unicode string
				strcat_s(parameterString, "\"");
				strcat_s(parameterString, (char*)(*((int*)&firstParameter + i)));
				strcat_s(parameterString, "\"");
				break;
			case 'y': //bytes
				break;
			default:
			case 'L': //long long
			case 'K': //unsigned long long
			case 'd': //double
				return;
			}
		}
		else
		{
			itoa(*((int*)&firstParameter + i), number, 10);
			strcat_s(parameterString, number);
		}
	}

	PyObject* v = PyLong_FromLong((long)hookFunctionAddress);
	PyObject_SetAttrString(PyImport_AddModule("__main__"), "HookFunctionAddress", v);
	Py_DECREF(v);

	PyObject* vDeclSpec = PyUnicode_FromString(declspec);
	PyObject_SetAttrString(PyImport_AddModule("__main__"), "HookDeclSpec", vDeclSpec);
	Py_DECREF(vDeclSpec);

	if (format)
	{
		PyObject* vFormat = PyUnicode_FromString(format);
		PyObject_SetAttrString(PyImport_AddModule("__main__"), "HookFormat", vFormat);
		Py_DECREF(vFormat);
	}

	char pythonString[1024];
	sprintf_s(pythonString, 
		"import os\n"
		"import sys\n"
		"sys.path.append(os.getcwd())\n"
		"from Hooks import *\n"
		"%s(%s)", functionName, parameterString);

	//printf("%s\n", pythonString);
	PyRun_SimpleString(pythonString);

	Py_Finalize();
}

int WriteByte(unsigned char* data, int index, unsigned char byte)
{
	data[index] = byte;
	return index + 1;
}

int WriteShort(unsigned char* data, int index, unsigned short s)
{
	*(unsigned short*)(data + index) = s;
	return index + 2;
}


int WriteInt(unsigned char* data, int index, int i)
{
	*(int*)(data + index) = i;
	return index + 4;
}

int WriteRelativeAddress(unsigned char* data, int index, int address)
{
	return WriteInt(data, index, address - (int)(data + index) - 4);
}

int WriteRelativeByteOffset(unsigned char* data, int index, int address)
{
	return WriteByte(data, index, address - (int)(data + index) - 1);
}

extern "C" _declspec(dllexport) void* PythonHook(const char* functionName, const char* declSpec, int parameters, const char* format)
{
	if (strcmp(declSpec, "cdecl") != 0 && strcmp(declSpec, "stdcall") != 0 && strcmp(declSpec, "thiscall") != 0)
	{
		printf("Invalid declspec.\r\n");
		return NULL;
	}

	int index = 0;
	unsigned char* function = (unsigned char*)VirtualAlloc(NULL, 512, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	index = WriteByte(function, index, 0x55); //push ebp

	index = WriteByte(function, index, 0x8B); //mov ebp, esp
	index = WriteByte(function, index, 0xEC);

	for (int i = parameters - 1; i >= 0; i--)
	{
		index = WriteByte(function, index, 0xFF); //push [ebp + 8 + 4 * i]
		index = WriteByte(function, index, 0x75);
		index = WriteByte(function, index, 8 + 4 * i);
	}

	if (strcmp(declSpec, "thiscall") == 0)
		index = WriteByte(function, index, 0x51); //push ecx

	index = WriteByte(function, index, 0x6A); //push parameters
	index = WriteByte(function, index, strcmp(declSpec, "thiscall") == 0 ? parameters + 1 : parameters);

	index = WriteByte(function, index, 0x68); //push format
	index = WriteInt(function, index, (int)format);

	index = WriteByte(function, index, 0x68); //push declSpec
	index = WriteInt(function, index, (int)declSpec);

	index = WriteByte(function, index, 0x68); //push functionName
	index = WriteInt(function, index, (int)functionName);

	index = WriteByte(function, index, 0x68); //push hookFunctionAddress (function)
	index = WriteInt(function, index, (int)function);

	index = WriteByte(function, index, 0xE8); //call CallPythonFunction
	index = WriteRelativeAddress(function, index, (int)&CallPythonFunction);

	index = WriteByte(function, index, 0x83); //add esp, 20  + 4 * parameters
	index = WriteByte(function, index, 0xC4);
	index = WriteByte(function, index, 20 + 4 * (strcmp(declSpec, "thiscall") == 0 ? parameters + 1 : parameters));

	index = WriteByte(function, index, 0x5D); //pop ebp

	if (strcmp(declSpec, "thiscall") == 0 || strcmp(declSpec, "stdcall") == 0)
	{
		index = WriteByte(function, index, 0xC2); //return 4 * parameters
		index = WriteShort(function, index, 4 * parameters);
	}
	else //if (strcmp(declSpec, "cdecl"))
		index = WriteByte(function, index, 0xC3); //return

	return function;
}

extern "C" _declspec(dllexport) void SetOriginalFunctionMapping(void* from, void* to)
{
	_originalFunctionMap[from] = to;
}

BOOL WINAPI DllMain(HINSTANCE module_handle, DWORD reason_for_call, LPVOID reserved)
{
	if (reason_for_call == DLL_PROCESS_ATTACH)
	{
		PyImport_AppendInittab("HookPython", &PyInit_HookPython);
		Py_SetProgramName(L"HookitHomie");
	}

	return TRUE;
}