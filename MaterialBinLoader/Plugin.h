#pragma once
#include <iostream>

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
		T& get() {
			return value;
		}
		operator T& () noexcept { return value; }
		operator T const& () const noexcept { return value; }
	};

};


