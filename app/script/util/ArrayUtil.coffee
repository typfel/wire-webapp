#
# Wire
# Copyright (C) 2016 Wire Swiss GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#

window.z ?= {}
z.util ?= {}


z.util.ArrayUtil =
  # returns chunks of the given size
  chunk: (array, size) ->
    chunks = []
    temp_array = [].concat array
    while temp_array.length
      chunks.push temp_array.splice 0, size
    return chunks

  find_closest: (array, value) ->
    closest = array[0]
    array.forEach (current) ->
      closest = current if value >= current
    return closest

  get_next_item: (array, item, filter) ->
    current_index = array.indexOf item
    # couldn't find the item
    return null if current_index is -1

    next_index = current_index + 1

    # item is last item in the array
    if next_index is array.length and current_index > 0
      return array[current_index - 1]

    return if next_index >= array.length

    for index in [next_index..array.length]
      next_item = array[index]
      return next_item unless filter? and not filter next_item

  ###
  Interpolates an array of numbers using linear interpolation

  @param array [Array] source
  @param length [Number] new length
  @return [Array] new array with interpolated values
  ###
  interpolate: (array, length) ->
    new_array = []
    scale_factor = (array.length - 1) / (length - 1)

    new_array[0] = array[0]
    new_array[length - 1] = array[array.length - 1]

    for i in [1...length - 1]
      original_index = i * scale_factor
      before = Math.floor(original_index).toFixed()
      after = Math.ceil(original_index).toFixed()
      point = original_index - before
      new_array[i] = array[before] + (array[after] - array[before]) * point # linear interpolation

    return new_array

  is_last_item: (array, item) ->
    return array.indexOf(item) is array.length - 1

  iterate_index: (array, current_index, reverse = false) ->
    return undefined if not _.isArray(array) or not _.isNumber current_index
    return undefined if not array.length
    if reverse
      return array.length - 1 if current_index is 0
      return (current_index - 1) % array.length
    return (current_index + 1) % array.length

  iterate_item: (array, current_item, reverse = false) ->
    return undefined if not _.isArray(array)
    return undefined if not array.length

    current_index = array.indexOf current_item
    return undefined if current_index is -1
    return array[z.util.ArrayUtil.iterate_index array, current_index, reverse]

  ###
  Returns random element
  @param array [Array] source
  @return [Object] random element
  ###
  random_element: (array = []) ->
    return array[Math.floor(Math.random() * array.length)]

  ###
  Remove given element from array
  @param array [Array] source
  @return [Array|undefined] containing the removed element
  ###
  remove_element: (array = [], element) ->
    index = array.indexOf element
    array.splice index, 1 if index > -1
