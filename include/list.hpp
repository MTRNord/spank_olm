#pragma once
#include <cstddef>
#include <iostream>
#include <utility>
#include <memory>

namespace spank_olm
{
    // Possibly should be replaced by implace_vector. For example https://godbolt.org/z/5P78aG5xE

    /**
     * \brief A fixed-size array implementation.
     *
     * \tparam T The type of elements stored in the array.
     * \tparam max_size The maximum number of elements the array can hold.
     */
    template <typename T, std::size_t max_size>
    class FixedSizeArray
    {
    public:
        /**
         * \brief Constructs an empty FixedSizeArray.
         */
        FixedSizeArray() : current_size(0)
        {
            data = std::make_unique<T*[]>(max_size + 1);
        }

        /**
         * \brief Copy constructor.
         *
         * \param other The FixedSizeArray to copy from.
         */
        FixedSizeArray(const FixedSizeArray& other)
            : current_size(other.current_size)
        {
            data = std::make_unique<T*[]>(max_size + 1);
            for (std::size_t i = 0; i < other.current_size; ++i)
            {
                data[i] = new T(*other.data[i]);
            }
        }


        /**
         * \brief Destroys the FixedSizeArray and frees allocated memory.
         */
        ~FixedSizeArray()
        {
            clear();
        }

        // Error codes
        enum ErrorCode
        {
            SUCCESS = 0, ///< Operation was successful.
            INDEX_OUT_OF_RANGE = 1 ///< Index was out of range.
        };

        /**
         * \brief Inserts a value at the beginning of the array.
         *
         * \param value The value to insert.
         * \return ErrorCode indicating the result of the operation.
         */
        constexpr ErrorCode insert(const T& value)
        {
            return insert_at(0, value);
        }

        /**
         * \brief Inserts a value at a specified index in the array.
         *
         * \param index The index at which to insert the value.
         * \param value The value to insert.
         * \return ErrorCode indicating the result of the operation.
         */
        constexpr ErrorCode insert_at(std::size_t index, const T& value)
        {
            if (index > current_size)
            {
                return INDEX_OUT_OF_RANGE;
            }
            if (current_size < max_size)
            {
                // Shift elements to the right
                for (std::size_t i = current_size; i > index; --i)
                {
                    data[i] = std::move(data[i - 1]);
                }
                data[index] = new T(value);
                ++current_size;
            }
            else
            {
                // Drop the last element and shift others to the right
                delete data[max_size - 1];
                for (std::size_t i = max_size - 1; i > index; --i)
                {
                    data[i] = std::move(data[i - 1]);
                }
                data[index] = new T(value);
            }

            return SUCCESS;
        }

        /**
         * \brief Erases the element at a specified index.
         *
         * \param index_given The index of the element to erase.
         * \return ErrorCode indicating the result of the operation.
         */
        constexpr ErrorCode erase_at(const std::size_t index_given)
        {
            // The list behaves reversed to the array, so we need to reverse the index
            const std::size_t index = current_size - index_given - 1;

            if (index >= current_size)
            {
                return INDEX_OUT_OF_RANGE;
            }
            delete data[index];
            for (std::size_t i = index; i < current_size - 1; ++i)
            {
                data[i] = std::move(data[i + 1]);
            }
            --current_size;
            return SUCCESS;
        }

        /**
         * \brief Erases the element at the specified pointer position.
         *
         * \param ptr The pointer to the element to erase.
         * \return ErrorCode indicating the result of the operation.
         */
        constexpr ErrorCode erase(T* const ptr)
        {
            for (std::size_t i = 0; i < current_size; ++i)
            {
                if (data[i] == ptr)
                {
                    return erase_at(i);
                }
            }
            return INDEX_OUT_OF_RANGE;
        }

        /**
         * \brief Accesses the element at a specified index.
         *
         * \param index The index of the element to access.
         * \return A reference to the element at the specified index.
         */
        constexpr T& operator[](std::size_t index)
        {
            return *data[index];
        }

        /**
         * \brief Accesses the element at a specified index (const version).
         *
         * \param index The index of the element to access.
         * \return A const reference to the element at the specified index.
         */
        constexpr const T& operator[](std::size_t index) const
        {
            return *data[index];
        }

        /**
         * \brief Assigns the contents of another FixedSizeArray to this one.
         *
         * \param other The FixedSizeArray to copy from.
         * \return A reference to this FixedSizeArray.
         */
        constexpr FixedSizeArray& operator=(const FixedSizeArray& other)
        {
            if (this != &other)
            {
                clear();
                data = std::make_unique<T*[]>(max_size);
                for (std::size_t i = 0; i < other.current_size; ++i)
                {
                    data[i] = new T(*other.data[i]);
                }
                current_size = other.current_size;
            }
            return *this;
        }

        /**
         * \brief Returns the number of elements in the array.
         *
         * \return The number of elements in the array.
         */
        [[nodiscard]] constexpr std::size_t size() const
        {
            return current_size;
        }

        /**
         * \brief Checks if the array is empty.
         *
         * \return True if the array is empty, false otherwise.
         */
        [[nodiscard]] constexpr bool empty() const
        {
            return current_size == 0;
        }

        // Iterator support
        using iterator = T**;
        using const_iterator = const T**;

        /**
         * \brief Returns an iterator to the beginning of the array.
         *
         * \return An iterator to the beginning of the array.
         */
        constexpr iterator begin() { return data.get(); }

        /**
         * \brief Returns a const iterator to the beginning of the array.
         *
         * \return A const iterator to the beginning of the array.
         */
        constexpr const_iterator begin() const { return const_cast<const_iterator>(data.get()); }

        /**
         * \brief Returns an iterator to the end of the array.
         *
         * \return An iterator to the end of the array.
         */
        constexpr iterator end() { return data.get() + current_size; }

        /**
         * \brief Returns a const iterator to the end of the array.
         *
         * \return A const iterator to the end of the array.
         */
        constexpr const_iterator end() const { return const_cast<const_iterator>(data.get() + current_size); }

    private:
        /**
         * \brief Clears the array and frees allocated memory.
         */
        void clear()
        {
            for (std::size_t i = 0; i < current_size; ++i)
            {
                delete data[i];
            }
            current_size = 0;
        }

        std::unique_ptr<T*[]> data; ///< Pointer to the array data.
        std::size_t current_size; ///< The current number of elements in the array.
    };
}
