#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_call_aes_t {
	sgx_status_t ms_retval;
	uint8_t* ms_ecBytes;
	uint32_t ms_ecBytesLen;
	uint8_t* ms_userIDBytes;
	uint32_t ms_userIDLength;
} ms_ecall_call_aes_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_data;
	uint32_t ms_data_size;
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_size;
	uint8_t* ms_unsealed_data;
	uint32_t ms_unsealed_size;
} ms_unseal_t;

typedef struct ms_ecall_calc_sealed_size_t {
	uint32_t ms_retval;
	uint32_t ms_data_size;
} ms_ecall_calc_sealed_size_t;

typedef struct ms_ecall_type_char_t {
	char ms_val;
} ms_ecall_type_char_t;

typedef struct ms_ecall_type_int_t {
	int ms_val;
} ms_ecall_type_int_t;

typedef struct ms_ecall_type_float_t {
	float ms_val;
} ms_ecall_type_float_t;

typedef struct ms_ecall_type_double_t {
	double ms_val;
} ms_ecall_type_double_t;

typedef struct ms_ecall_type_size_t_t {
	size_t ms_val;
} ms_ecall_type_size_t_t;

typedef struct ms_ecall_type_wchar_t_t {
	wchar_t ms_val;
} ms_ecall_type_wchar_t_t;

typedef struct ms_ecall_type_struct_t {
	struct struct_foo_t ms_val;
} ms_ecall_type_struct_t;

typedef struct ms_ecall_type_enum_union_t {
	enum enum_foo_t ms_val1;
	union union_foo_t* ms_val2;
} ms_ecall_type_enum_union_t;

typedef struct ms_ecall_pointer_user_check_t {
	size_t ms_retval;
	void* ms_val;
	size_t ms_sz;
} ms_ecall_pointer_user_check_t;

typedef struct ms_ecall_pointer_in_t {
	int* ms_val;
} ms_ecall_pointer_in_t;

typedef struct ms_ecall_pointer_out_t {
	int* ms_val;
} ms_ecall_pointer_out_t;

typedef struct ms_ecall_pointer_in_out_t {
	int* ms_val;
} ms_ecall_pointer_in_out_t;

typedef struct ms_ecall_pointer_string_t {
	char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_t;

typedef struct ms_ecall_pointer_string_const_t {
	const char* ms_str;
	size_t ms_str_len;
} ms_ecall_pointer_string_const_t;

typedef struct ms_ecall_pointer_size_t {
	void* ms_ptr;
	size_t ms_len;
} ms_ecall_pointer_size_t;

typedef struct ms_ecall_pointer_count_t {
	int* ms_arr;
	size_t ms_cnt;
} ms_ecall_pointer_count_t;

typedef struct ms_ecall_pointer_isptr_readonly_t {
	buffer_t ms_buf;
	size_t ms_len;
} ms_ecall_pointer_isptr_readonly_t;

typedef struct ms_ecall_array_user_check_t {
	int* ms_arr;
} ms_ecall_array_user_check_t;

typedef struct ms_ecall_array_in_t {
	int* ms_arr;
} ms_ecall_array_in_t;

typedef struct ms_ecall_array_out_t {
	int* ms_arr;
} ms_ecall_array_out_t;

typedef struct ms_ecall_array_in_out_t {
	int* ms_arr;
} ms_ecall_array_in_out_t;

typedef struct ms_ecall_array_isary_t {
	array_t*  ms_arr;
} ms_ecall_array_isary_t;

typedef struct ms_ecall_function_private_t {
	int ms_retval;
} ms_ecall_function_private_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ecall_increase_counter_t {
	size_t ms_retval;
} ms_ecall_increase_counter_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_pointer_user_check_t {
	int* ms_val;
} ms_ocall_pointer_user_check_t;

typedef struct ms_ocall_pointer_in_t {
	int* ms_val;
} ms_ocall_pointer_in_t;

typedef struct ms_ocall_pointer_out_t {
	int* ms_val;
} ms_ocall_pointer_out_t;

typedef struct ms_ocall_pointer_in_out_t {
	int* ms_val;
} ms_ocall_pointer_in_out_t;

typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	const void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#pragma warning(disable: 4090)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_call_aes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_call_aes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_call_aes_t* ms = SGX_CAST(ms_ecall_call_aes_t*, pms);
	ms_ecall_call_aes_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_call_aes_t), ms, sizeof(ms_ecall_call_aes_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ecBytes = __in_ms.ms_ecBytes;
	uint32_t _tmp_ecBytesLen = __in_ms.ms_ecBytesLen;
	size_t _len_ecBytes = _tmp_ecBytesLen;
	uint8_t* _in_ecBytes = NULL;
	uint8_t* _tmp_userIDBytes = __in_ms.ms_userIDBytes;
	uint32_t _tmp_userIDLength = __in_ms.ms_userIDLength;
	size_t _len_userIDBytes = _tmp_userIDLength;
	uint8_t* _in_userIDBytes = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_ecBytes, _len_ecBytes);
	CHECK_UNIQUE_POINTER(_tmp_userIDBytes, _len_userIDBytes);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ecBytes != NULL && _len_ecBytes != 0) {
		if ( _len_ecBytes % sizeof(*_tmp_ecBytes) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ecBytes = (uint8_t*)malloc(_len_ecBytes);
		if (_in_ecBytes == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ecBytes, _len_ecBytes, _tmp_ecBytes, _len_ecBytes)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_userIDBytes != NULL && _len_userIDBytes != 0) {
		if ( _len_userIDBytes % sizeof(*_tmp_userIDBytes) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_userIDBytes = (uint8_t*)malloc(_len_userIDBytes);
		if (_in_userIDBytes == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_userIDBytes, _len_userIDBytes, _tmp_userIDBytes, _len_userIDBytes)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_call_aes(_in_ecBytes, _tmp_ecBytesLen, _in_userIDBytes, _tmp_userIDLength);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_ecBytes) free(_in_ecBytes);
	if (_in_userIDBytes) free(_in_userIDBytes);
	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	ms_seal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_seal_t), ms, sizeof(ms_seal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = __in_ms.ms_data;
	uint32_t _tmp_data_size = __in_ms.ms_data_size;
	size_t _len_data = _tmp_data_size;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	uint8_t* _in_sealed_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		if ( _len_data % sizeof(*_tmp_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (uint8_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	_in_retval = seal(_in_data, _tmp_data_size, _in_sealed_data, _tmp_sealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_data) free(_in_data);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	ms_unseal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_unseal_t), ms, sizeof(ms_unseal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	uint8_t* _in_sealed_data = NULL;
	uint8_t* _tmp_unsealed_data = __in_ms.ms_unsealed_data;
	uint32_t _tmp_unsealed_size = __in_ms.ms_unsealed_size;
	size_t _len_unsealed_data = _tmp_unsealed_size;
	uint8_t* _in_unsealed_data = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_unsealed_data, _len_unsealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (uint8_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_unsealed_data != NULL && _len_unsealed_data != 0) {
		if ( _len_unsealed_data % sizeof(*_tmp_unsealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_unsealed_data = (uint8_t*)malloc(_len_unsealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unsealed_data, 0, _len_unsealed_data);
	}
	_in_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_unsealed_data, _tmp_unsealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_unsealed_data) {
		if (memcpy_verw_s(_tmp_unsealed_data, _len_unsealed_data, _in_unsealed_data, _len_unsealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_unsealed_data) free(_in_unsealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_calc_sealed_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_calc_sealed_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_calc_sealed_size_t* ms = SGX_CAST(ms_ecall_calc_sealed_size_t*, pms);
	ms_ecall_calc_sealed_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_calc_sealed_size_t), ms, sizeof(ms_ecall_calc_sealed_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t _in_retval;


	_in_retval = ecall_calc_sealed_size(__in_ms.ms_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_char(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_char_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_char_t* ms = SGX_CAST(ms_ecall_type_char_t*, pms);
	ms_ecall_type_char_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_char_t), ms, sizeof(ms_ecall_type_char_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_char(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_int(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_int_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_int_t* ms = SGX_CAST(ms_ecall_type_int_t*, pms);
	ms_ecall_type_int_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_int_t), ms, sizeof(ms_ecall_type_int_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_int(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_float(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_float_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_float_t* ms = SGX_CAST(ms_ecall_type_float_t*, pms);
	ms_ecall_type_float_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_float_t), ms, sizeof(ms_ecall_type_float_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_float(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_double(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_double_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_double_t* ms = SGX_CAST(ms_ecall_type_double_t*, pms);
	ms_ecall_type_double_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_double_t), ms, sizeof(ms_ecall_type_double_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_double(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_size_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_size_t_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_size_t_t* ms = SGX_CAST(ms_ecall_type_size_t_t*, pms);
	ms_ecall_type_size_t_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_size_t_t), ms, sizeof(ms_ecall_type_size_t_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_size_t(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_wchar_t(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_wchar_t_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_wchar_t_t* ms = SGX_CAST(ms_ecall_type_wchar_t_t*, pms);
	ms_ecall_type_wchar_t_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_wchar_t_t), ms, sizeof(ms_ecall_type_wchar_t_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_wchar_t(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_struct(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_struct_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_struct_t* ms = SGX_CAST(ms_ecall_type_struct_t*, pms);
	ms_ecall_type_struct_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_struct_t), ms, sizeof(ms_ecall_type_struct_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_type_struct(__in_ms.ms_val);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_type_enum_union(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_type_enum_union_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_type_enum_union_t* ms = SGX_CAST(ms_ecall_type_enum_union_t*, pms);
	ms_ecall_type_enum_union_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_type_enum_union_t), ms, sizeof(ms_ecall_type_enum_union_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	union union_foo_t* _tmp_val2 = __in_ms.ms_val2;


	ecall_type_enum_union(__in_ms.ms_val1, _tmp_val2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_user_check_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_user_check_t* ms = SGX_CAST(ms_ecall_pointer_user_check_t*, pms);
	ms_ecall_pointer_user_check_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_user_check_t), ms, sizeof(ms_ecall_pointer_user_check_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_val = __in_ms.ms_val;
	size_t _in_retval;


	_in_retval = ecall_pointer_user_check(_tmp_val, __in_ms.ms_sz);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_in_t* ms = SGX_CAST(ms_ecall_pointer_in_t*, pms);
	ms_ecall_pointer_in_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_in_t), ms, sizeof(ms_ecall_pointer_in_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = __in_ms.ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_val, _len_val, _tmp_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_pointer_in(_in_val);

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_out_t* ms = SGX_CAST(ms_ecall_pointer_out_t*, pms);
	ms_ecall_pointer_out_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_out_t), ms, sizeof(ms_ecall_pointer_out_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = __in_ms.ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_val = (int*)malloc(_len_val)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_val, 0, _len_val);
	}
	ecall_pointer_out(_in_val);
	if (_in_val) {
		if (memcpy_verw_s(_tmp_val, _len_val, _in_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_in_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_in_out_t* ms = SGX_CAST(ms_ecall_pointer_in_out_t*, pms);
	ms_ecall_pointer_in_out_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_in_out_t), ms, sizeof(ms_ecall_pointer_in_out_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_val = __in_ms.ms_val;
	size_t _len_val = sizeof(int);
	int* _in_val = NULL;

	CHECK_UNIQUE_POINTER(_tmp_val, _len_val);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_val != NULL && _len_val != 0) {
		if ( _len_val % sizeof(*_tmp_val) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_val = (int*)malloc(_len_val);
		if (_in_val == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_val, _len_val, _tmp_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_pointer_in_out(_in_val);
	if (_in_val) {
		if (memcpy_verw_s(_tmp_val, _len_val, _in_val, _len_val)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_val) free(_in_val);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_string_t* ms = SGX_CAST(ms_ecall_pointer_string_t*, pms);
	ms_ecall_pointer_string_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_string_t), ms, sizeof(ms_ecall_pointer_string_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_str = __in_ms.ms_str;
	size_t _len_str = __in_ms.ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_pointer_string(_in_str);
	if (_in_str)
	{
		_in_str[_len_str - 1] = '\0';
		_len_str = strlen(_in_str) + 1;
		if (memcpy_verw_s((void*)_tmp_str, _len_str, _in_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_string_const(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_string_const_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_string_const_t* ms = SGX_CAST(ms_ecall_pointer_string_const_t*, pms);
	ms_ecall_pointer_string_const_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_string_const_t), ms, sizeof(ms_ecall_pointer_string_const_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_str = __in_ms.ms_str;
	size_t _len_str = __in_ms.ms_str_len ;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_str[_len_str - 1] = '\0';
		if (_len_str != strlen(_in_str) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	ecall_pointer_string_const((const char*)_in_str);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_size_t* ms = SGX_CAST(ms_ecall_pointer_size_t*, pms);
	ms_ecall_pointer_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_size_t), ms, sizeof(ms_ecall_pointer_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_ptr = __in_ms.ms_ptr;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_ptr = _tmp_len;
	void* _in_ptr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ptr != NULL && _len_ptr != 0) {
		_in_ptr = (void*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ptr, _len_ptr, _tmp_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_pointer_size(_in_ptr, _tmp_len);
	if (_in_ptr) {
		if (memcpy_verw_s(_tmp_ptr, _len_ptr, _in_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ptr) free(_in_ptr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_count_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_count_t* ms = SGX_CAST(ms_ecall_pointer_count_t*, pms);
	ms_ecall_pointer_count_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_count_t), ms, sizeof(ms_ecall_pointer_count_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = __in_ms.ms_arr;
	size_t _tmp_cnt = __in_ms.ms_cnt;
	size_t _len_arr = _tmp_cnt * sizeof(int);
	int* _in_arr = NULL;

	if (sizeof(*_tmp_arr) != 0 &&
		(size_t)_tmp_cnt > (SIZE_MAX / sizeof(*_tmp_arr))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_pointer_count(_in_arr, _tmp_cnt);
	if (_in_arr) {
		if (memcpy_verw_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pointer_isptr_readonly(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pointer_isptr_readonly_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pointer_isptr_readonly_t* ms = SGX_CAST(ms_ecall_pointer_isptr_readonly_t*, pms);
	ms_ecall_pointer_isptr_readonly_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_pointer_isptr_readonly_t), ms, sizeof(ms_ecall_pointer_isptr_readonly_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	buffer_t _tmp_buf = __in_ms.ms_buf;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_buf = _tmp_len;
	buffer_t _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		_in_buf = (buffer_t)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_pointer_isptr_readonly(_in_buf, _tmp_len);

err:
	if (_in_buf) free((void*)_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ocall_pointer_attr(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_pointer_attr();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_user_check(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_user_check_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_user_check_t* ms = SGX_CAST(ms_ecall_array_user_check_t*, pms);
	ms_ecall_array_user_check_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_array_user_check_t), ms, sizeof(ms_ecall_array_user_check_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = __in_ms.ms_arr;


	ecall_array_user_check(_tmp_arr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_in_t* ms = SGX_CAST(ms_ecall_array_in_t*, pms);
	ms_ecall_array_in_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_array_in_t), ms, sizeof(ms_ecall_array_in_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = __in_ms.ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_array_in(_in_arr);

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_out_t* ms = SGX_CAST(ms_ecall_array_out_t*, pms);
	ms_ecall_array_out_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_array_out_t), ms, sizeof(ms_ecall_array_out_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = __in_ms.ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_arr = (int*)malloc(_len_arr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_arr, 0, _len_arr);
	}
	ecall_array_out(_in_arr);
	if (_in_arr) {
		if (memcpy_verw_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_in_out(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_in_out_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_in_out_t* ms = SGX_CAST(ms_ecall_array_in_out_t*, pms);
	ms_ecall_array_in_out_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_array_in_out_t), ms, sizeof(ms_ecall_array_in_out_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_arr = __in_ms.ms_arr;
	size_t _len_arr = 4 * sizeof(int);
	int* _in_arr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_arr, _len_arr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_arr != NULL && _len_arr != 0) {
		if ( _len_arr % sizeof(*_tmp_arr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_arr = (int*)malloc(_len_arr);
		if (_in_arr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_arr, _len_arr, _tmp_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_array_in_out(_in_arr);
	if (_in_arr) {
		if (memcpy_verw_s(_tmp_arr, _len_arr, _in_arr, _len_arr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_arr) free(_in_arr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_isary(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_isary_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_array_isary_t* ms = SGX_CAST(ms_ecall_array_isary_t*, pms);
	ms_ecall_array_isary_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_array_isary_t), ms, sizeof(ms_ecall_array_isary_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;


	ecall_array_isary((__in_ms.ms_arr != NULL) ? (*__in_ms.ms_arr) : NULL);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_public(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_public();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_function_private(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_function_private_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_function_private_t* ms = SGX_CAST(ms_ecall_function_private_t*, pms);
	ms_ecall_function_private_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_function_private_t), ms, sizeof(ms_ecall_function_private_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_function_private();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_malloc_free(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_malloc_free();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sgx_cpuid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sgx_cpuid_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_sgx_cpuid_t* ms = SGX_CAST(ms_ecall_sgx_cpuid_t*, pms);
	ms_ecall_sgx_cpuid_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_sgx_cpuid_t), ms, sizeof(ms_ecall_sgx_cpuid_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cpuinfo = __in_ms.ms_cpuinfo;
	size_t _len_cpuinfo = 4 * sizeof(int);
	int* _in_cpuinfo = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cpuinfo, _len_cpuinfo);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cpuinfo != NULL && _len_cpuinfo != 0) {
		if ( _len_cpuinfo % sizeof(*_tmp_cpuinfo) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_cpuinfo = (int*)malloc(_len_cpuinfo)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cpuinfo, 0, _len_cpuinfo);
	}
	ecall_sgx_cpuid(_in_cpuinfo, __in_ms.ms_leaf);
	if (_in_cpuinfo) {
		if (memcpy_verw_s(_tmp_cpuinfo, _len_cpuinfo, _in_cpuinfo, _len_cpuinfo)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_cpuinfo) free(_in_cpuinfo);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_exception(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_exception();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_map(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_map();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_increase_counter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_increase_counter_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_increase_counter_t* ms = SGX_CAST(ms_ecall_increase_counter_t*, pms);
	ms_ecall_increase_counter_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_increase_counter_t), ms, sizeof(ms_ecall_increase_counter_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	size_t _in_retval;


	_in_retval = ecall_increase_counter();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_producer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_producer();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_consumer(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_consumer();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[37];
} g_ecall_table = {
	37,
	{
		{(void*)(uintptr_t)sgx_ecall_call_aes, 0, 0},
		{(void*)(uintptr_t)sgx_seal, 0, 0},
		{(void*)(uintptr_t)sgx_unseal, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_calc_sealed_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_char, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_int, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_float, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_double, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_size_t, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_wchar_t, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_struct, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_type_enum_union, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_user_check, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_in_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_string_const, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_count, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_pointer_isptr_readonly, 0, 0},
		{(void*)(uintptr_t)sgx_ocall_pointer_attr, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_user_check, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_in_out, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_array_isary, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_public, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_function_private, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_malloc_free, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_sgx_cpuid, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_exception, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_map, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_increase_counter, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_producer, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_consumer, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[12][37];
} g_dyn_entry_table = {
	12,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_user_check(int* val)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_pointer_user_check_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_user_check_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_user_check_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_user_check_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_user_check_t);

	if (memcpy_verw_s(&ms->ms_val, sizeof(ms->ms_val), &val, sizeof(val))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_in_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_in_t);

	if (val != NULL) {
		if (memcpy_verw_s(&ms->ms_val, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, val, _len_val)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_out_t);
	void *__tmp = NULL;

	void *__tmp_val = NULL;

	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_out_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_out_t);

	if (val != NULL) {
		if (memcpy_verw_s(&ms->ms_val, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_val = __tmp;
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_val, 0, _len_val);
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (val) {
			if (memcpy_s((void*)val, _len_val, __tmp_val, _len_val)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_pointer_in_out(int* val)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_val = sizeof(int);

	ms_ocall_pointer_in_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_pointer_in_out_t);
	void *__tmp = NULL;

	void *__tmp_val = NULL;

	CHECK_ENCLAVE_POINTER(val, _len_val);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (val != NULL) ? _len_val : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_pointer_in_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_pointer_in_out_t));
	ocalloc_size -= sizeof(ms_ocall_pointer_in_out_t);

	if (val != NULL) {
		if (memcpy_verw_s(&ms->ms_val, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_val = __tmp;
		if (_len_val % sizeof(*val) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, val, _len_val)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_val);
		ocalloc_size -= _len_val;
	} else {
		ms->ms_val = NULL;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (val) {
			if (memcpy_s((void*)val, _len_val, __tmp_val, _len_val)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	void *__tmp_dest = NULL;

	CHECK_ENCLAVE_POINTER(dest, _len_dest);
	CHECK_ENCLAVE_POINTER(src, _len_src);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dest != NULL) ? _len_dest : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (src != NULL) ? _len_src : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));
	ocalloc_size -= sizeof(ms_memccpy_t);

	if (dest != NULL) {
		if (memcpy_verw_s(&ms->ms_dest, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dest = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, dest, _len_dest)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dest);
		ocalloc_size -= _len_dest;
	} else {
		ms->ms_dest = NULL;
	}

	if (src != NULL) {
		if (memcpy_verw_s(&ms->ms_src, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, src, _len_src)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_src);
		ocalloc_size -= _len_src;
	} else {
		ms->ms_src = NULL;
	}

	if (memcpy_verw_s(&ms->ms_val, sizeof(ms->ms_val), &val, sizeof(val))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dest) {
			if (memcpy_s((void*)dest, _len_dest, __tmp_dest, _len_dest)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_function_allow(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

	return status;
}
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
