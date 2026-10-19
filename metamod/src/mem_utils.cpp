#include "precompiled.h"

static_allocator::static_allocator(memory_protection protection) : m_protection(protection)
{
}

char *static_allocator::allocate(const size_t n)
{
	// requests larger than a page get their own block, the current page stays open for small allocations
	if (n > Pagesize)
		return allocate_block((n + Pagesize - 1) & ~size_t(Pagesize - 1));

	if (!m_page || m_used + n > Pagesize)
		allocate_page();

	auto ptr = m_page + m_used;
	m_used += n;
	return ptr;
}

char *static_allocator::strdup(const char *string)
{
	size_t len = Q_strlen(string) + 1;
	return (char *)Q_memcpy(allocate(len), string, len);
}

void static_allocator::deallocate_all()
{
	for (auto& block : m_pages)
#ifdef WIN32
		VirtualFree(block.ptr, 0, MEM_RELEASE);
#else
		munmap(block.ptr, block.size);
#endif

	m_pages.clear();
	m_page = nullptr;
	m_used = 0;
}

size_t static_allocator::memory_used() const
{
	size_t used = 0;
	for (auto& block : m_pages)
		used += block.size;

	if (m_page)
		used -= Pagesize - m_used;

	return used;
}

bool static_allocator::contain(uint32 addr)
{
	for (auto& block : m_pages) {
		if (uint32(block.ptr) <= addr && addr < uint32(block.ptr) + block.size)
			return true;
	}
	return false;
}

char *static_allocator::find_pattern(char *pattern, size_t len)
{
	for (auto& block : m_pages) {
		for (char *c = (char *)block.ptr, *e = c + block.size - len; c < e; c++) {
			if (mem_compare(c, pattern, len))
				return c;
		}
	}
	return nullptr;
}

void static_allocator::allocate_page()
{
	m_page = allocate_block(Pagesize);
	m_used = 0;
}

char *static_allocator::allocate_block(size_t size)
{
#ifdef WIN32
	auto ptr = VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!ptr)
#else
	auto ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED)
#endif
		Sys_Error("%s: failed to allocate %u bytes of executable memory", __func__, (unsigned)size);

	m_pages.push_back({ptr, size});
	return (char *)ptr;
}

bool mem_compare(const char *addr, const char *pattern, size_t len)
{
	for (auto c = pattern, pattern_end = pattern + len; c < pattern_end; ++c, ++addr) {
		if (*c == *addr || *c == '\x2A')
			continue;
		return false;
	}
	return true;
}

char *mem_find_pattern(char *pos, int range, const char *pattern, size_t len)
{
	for (auto c = pos + range - len; pos < c; ++pos) {
		if (mem_compare(pos, pattern, len))
			return pos;
	}

	return nullptr;
}

char *mem_find_ref(char *pos, char *end, char opcode, uint32 ref, bool relative)
{
	for (; pos < end; ++pos)
	{
		if (*pos == opcode)
		{
			if (relative)
			{
				if ((uint32)pos + 5 + *(uint32 *)(pos + 1) == ref)
					return pos;
			}
			else
			{
				if (*(uint32 *)(pos + 1) == ref)
					return pos;
			}
		}
	}

	return nullptr;
}

char *mem_find_string_push(char *addr, const char *string, size_t len)
{
	char *ptr = mem_find_pattern(addr, len, string, Q_strlen(string) + 1);
	return mem_find_ref(addr, addr + len - 5, '\x68', (uint32)ptr, false);
}
