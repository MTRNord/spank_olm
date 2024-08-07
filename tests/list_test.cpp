#include <iostream>
#include <snitch/snitch.hpp>
#include <list.hpp>

TEST_CASE("FixedSizeArray basic operations")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;

    // Test insertion
    REQUIRE(array.insert_at(0, 10) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.insert_at(1, 20) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.insert_at(1, 15) == FixedSizeArray<int, 5>::SUCCESS);

    // Test size
    REQUIRE(array.size() == 3);

    // Test element values
    // Test element values
    REQUIRE(array[0] == 10);
    REQUIRE(array[1] == 15);
    REQUIRE(array[2] == 20);

    // Test erasure
    REQUIRE(array.erase_at(1) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.size() == 2);
    REQUIRE(array[1] == 20);

    // Test boundary conditions
    REQUIRE(array.insert_at(5, 30) == FixedSizeArray<int, 5>::INDEX_OUT_OF_RANGE);
    REQUIRE(array.erase_at(5) == FixedSizeArray<int, 5>::INDEX_OUT_OF_RANGE);

    // Ensure iterator works
    int expected_values[] = {10, 20};
    int i = 0;
    for (const auto& value : array)
    {
        REQUIRE(*value == expected_values[i++]);
    }

    // Ensure that adding more elements than the maximum size is possible and the last element is dropped as expected
    // Loop to insert elements into the array, starting from 0 up to 9
    // This will cause the array to overflow, and only the last 5 elements will be kept
    for (int j = 0; j < 10; ++j)
    {
        array.insert_at(0, j);
    }

    // Check that the array size is 5 after the overflow
    REQUIRE(array.size() == 5);

    // Loop to verify that the elements in the array are as expected
    // The array should contain the last 5 inserted elements in reverse order
    for (int j = 0; j < 5; ++j)
    {
        REQUIRE(array[j] == 9 - j);
    }
}

TEST_CASE("FixedSizeArray erase element at pointer null")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;
    array.insert(1);
    array.insert(2);
    array.insert(3);

    int* ptr = nullptr;
    REQUIRE(array.erase(ptr) == FixedSizeArray<int, 5>::INDEX_OUT_OF_RANGE);
    REQUIRE(array.size() == 3);
}

TEST_CASE("FixedSizeArray erase first element")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;
    array.insert(1);
    array.insert(2);
    array.insert(3);
    REQUIRE(array.size() == 3);

    REQUIRE(array.erase_at(0) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.size() == 2);

    REQUIRE(array[1] == 2);
    REQUIRE(array[0] == 3);
}

TEST_CASE("FixedSizeArray erase last element")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;
    array.insert(1);
    array.insert(2);
    array.insert(3);

    int last_index = array.size() - 1;
    REQUIRE(array.erase_at(last_index) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.size() == 2);
    REQUIRE(array[0] == 2);
    REQUIRE(array[1] == 1);
}

TEST_CASE("FixedSizeArray erase element in full array")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;
    for (int i = 0; i < 5; ++i)
    {
        array.insert(i);
    }

    REQUIRE(array.erase_at(2) == FixedSizeArray<int, 5>::SUCCESS);
    REQUIRE(array.size() == 4);
    REQUIRE(array[0] == 4);
    REQUIRE(array[1] == 3);
    REQUIRE(array[2] == 1);
    REQUIRE(array[3] == 0);
}

TEST_CASE("FixedSizeArray erase element in empty array")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;

    int value = 1;
    int* ptr = &value;
    REQUIRE(array.erase(ptr) == FixedSizeArray<int, 5>::INDEX_OUT_OF_RANGE);
    REQUIRE(array.size() == 0);
}

TEST_CASE("FixedSizeArray empty and size match")
{
    using namespace spank_olm;

    FixedSizeArray<int, 5> array;

    // Initially, the array should be empty
    REQUIRE(array.empty() == true);
    REQUIRE(array.size() == 0);

    // Insert an element and check again
    array.insert(1);
    REQUIRE(array.empty() == false);
    REQUIRE(array.size() == 1);

    // Insert another element and check again
    array.insert(2);
    REQUIRE(array.empty() == false);
    REQUIRE(array.size() == 2);

    // Erase an element and check again
    array.erase_at(0);
    REQUIRE(array.empty() == false);
    REQUIRE(array.size() == 1);

    // Erase the last element and check again
    array.erase_at(0);
    REQUIRE(array.empty() == true);
    REQUIRE(array.size() == 0);
}
