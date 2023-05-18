#pragma once
#include <iostream>
#include <string>
#include <filesystem>

namespace Core {

	class PathPart {
	public:
		std::string mUtf8StdString;
	};

	class Path {
	public:
		PathPart mPath;
		Path(std::string a1) {
			mPath.mUtf8StdString = a1;
		}

	};

	template <typename T>
	class PathBuffer {
		T value;
	public:
		PathBuffer() {};
		PathBuffer(T v) {
			value = v;
		}
		T& get() {
			return value;
		}

		operator T& () noexcept { return value; }
		operator T const& () const noexcept { return value; }
	};

};

constexpr uint64_t do_hash(std::string_view x) {
	// ap hash
	uint64_t rval = 0;
	for (size_t i = 0; i < x.size(); ++i) {
		rval *= 128;
		rval += x[i];
		rval += 4;
	}
	return rval;
}

constexpr uint64_t do_hash2(const char* str) {
	// ap hash
	auto stra = str;
	uint64_t ret = 0xCBF29CE484222325LL;
	if (str)
	{
		while (*stra)
		{
			auto v1 = stra++;
			ret = *(unsigned __int8*)v1 ^ (0x100000001B3LL * ret);
		}
	}
	return ret;
}

class ResourceLocation
{
public:
	int32_t mFileSystem;
	Core::PathBuffer<std::string> mPath;
	uint64_t mPathHash;
	size_t mFullHash;
	ResourceLocation() {};
	ResourceLocation(std::string path) {
		mFileSystem = 0;
		mPath = Core::PathBuffer<std::string>::PathBuffer(path);
		_computeHashes();
	}
	void _computeHashes() {
		auto hash = do_hash2(this->mPath.get().c_str());
		this->mPathHash = hash;
		this->mFullHash = std::hash<unsigned char>{}(this->mFileSystem) ^ hash;
	}
};



class ResourcePackManager {
public:
	virtual ~ResourcePackManager();
	virtual bool load(class ResourceLocation const&, std::string&) const;
	virtual bool load(class ResourceLocation const&, std::string&, std::vector<std::string> const&) const;
	virtual bool load(class ResourceLocationPair const&, std::string&, std::vector<std::string> const&) const;
	virtual std::vector<class LoadedResourceData> loadAllVersionsOf(class ResourceLocation const&) const;
	virtual bool isInStreamableLocation(class ResourceLocation const&) const;
	virtual bool isInStreamableLocation(class ResourceLocation const&, std::vector<std::string> const&) const;
	virtual class Core::PathBuffer<std::string> getPath(class ResourceLocation const&) const;
	virtual class Core::PathBuffer<std::string> getPath(class ResourceLocation const&, std::vector<std::string> const&) const;
	virtual class Core::PathBuffer<std::string> getPathContainingResource(class ResourceLocation const&) const;
	virtual class Core::PathBuffer<std::string> getPathContainingResource(class ResourceLocation const&, std::vector<std::string>) const;
	virtual struct std::pair<int, std::string const&> getPackStackIndexOfResource(class ResourceLocation const&, std::vector<std::string> const&) const;
	virtual bool hasCapability(class std::basic_string_view<char, struct std::char_traits<char>>) const;
};

std::vector<std::string> SplitStrWithPattern(const std::string& str, const std::string& pattern) {
	std::vector<std::string> resVec;

	if (str.empty())
		return resVec;

	std::string strs = str + pattern;

	size_t pos = strs.find(pattern);
	size_t size = strs.size();

	while (pos != std::string::npos) {
		std::string x = strs.substr(0, pos);
		resVec.push_back(x);
		strs = strs.substr(pos + pattern.size(), size);
		pos = strs.find(pattern);
	}

	return resVec;
}

struct Version {

	int major;
	int minor;
	int revision;
	int status;

	explicit Version(int major = 0, int minor = 0, int revision = 0, int status = 0) : major(major), minor(minor), revision(revision), status(status) {};

	bool operator<(Version b) {
		return major < b.major || (major == b.major && minor < b.minor) ||
			(major == b.major && minor == b.minor && revision < b.revision) || (major == b.major && minor == b.minor && revision == b.revision && status < b.status);
	}
	bool operator==(Version b) {
		return major == b.major && minor == b.minor && revision == b.revision && status == b.status;
	}

	bool operator>(Version b) {
		return major > b.major || (major == b.major && minor > b.minor) ||
			(major == b.major && minor == b.minor && revision > b.revision) || (major == b.major && minor == b.minor && revision == b.revision && status > b.status);
	}

	bool operator>=(Version b) {
		return *this > b || *this == b;

	}

	bool operator<=(Version b) {
		return *this < b || *this == b;
	}

	static Version parse(const std::string& str) {
		Version ver;
		std::string a = str;
		std::string status;
		size_t pos = 0;

		auto res = SplitStrWithPattern(a, ".");

		if (res.size() >= 1)
			ver.major = stoi(res[0]);
		if (res.size() >= 2)
			ver.minor = stoi(res[1]);
		if (res.size() >= 3)
			ver.revision = stoi(res[2]);
		if (res.size() >= 4)
			ver.revision = stoi(res[3]);

		return ver;
	}
}; 